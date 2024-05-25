defmodule Teiserver.Tachyon.TachyonSocket do
  @behaviour Phoenix.Socket.Transport

  require Logger
  alias ExULID.ULID
  alias Phoenix.PubSub
  alias Teiserver.Config
  alias Teiserver.Account
  alias Teiserver.Tachyon.{CommandDispatch, MessageHandlers}
  alias Teiserver.Tachyon.Handlers
  alias Teiserver.Tachyon.Responses.System.ErrorResponse
  # alias Teiserver.Tachyon.Socket.PubsubHandlers
  alias Teiserver.Tachyon.Types, as: T

  @spec child_spec(any) :: :ignore
  def child_spec(_opts) do
    # We won't spawn any process, so let's return a dummy task
    # %{id: __MODULE__, start: {Task, :start_link, [fn -> :ok end]}, restart: :transient}
    :ignore
  end

  @spec connect(map()) ::
          {:ok, T.ws_state()} | {:error, atom | String.t()}
  def connect(
        %{
          params: %{
            "token" => token_value,
            "application_hash" => _,
            "application_name" => _,
            "application_version" => _
          }
        } = state
      ) do
    case Account.get_user_token_by_value(token_value) do
      nil ->
        {:error, :no_user}

      %{user: _user, expires: _expires} = token ->
        case login(token, state) do
          {:ok, conn} ->
            {:ok, Map.put(state, :conn, conn)}

          v ->
            Logger.error(
              "Error at: #{__ENV__.file}:#{__ENV__.line} - Login failure with token: #{inspect(v)}\n"
            )

            {:error, :failed_login}
        end

      value ->
        Logger.error(
          "Error at: #{__ENV__.file}:#{__ENV__.line} - No handler for value of #{inspect(value)}"
        )

        {:error, :unexpected_value}
    end
  end

  def connect(%{params: params}) do
    missing =
      ~w(token application_hash application_name application_version)
      |> Enum.reject(fn key -> Map.has_key?(params, key) end)
      |> Enum.join(", ")

    {:error, "missing_params: #{missing}"}
  end

  @spec init(T.ws_state()) :: {:ok, T.ws_state()}
  def init(%{conn: %{userid: userid}} = state) do
    # Not sure why there was a timer for this. For now, just disable the delay
    # until we implement the protocol and this does things
    # :timer.send_after(1500, :connect_to_client)
    send(self(), :connect_to_client)

    Logger.metadata(request_id: "TachyonWSServer##{userid}")
    :ok = PubSub.subscribe(Teiserver.PubSub, "teiserver_client_messages:#{userid}")
    :ok = PubSub.subscribe(Teiserver.PubSub, "teiserver_server")

    {:ok, state}
  end

  # Example of a good whoami request
  # {"command": "account/whoAmI/request", "data": {}}

  # @spec handle_in({atom, any}, T.ws_state()) :: {:ok, T.ws_state()} | {:reply, :ok, {:text, String.t()}, T.ws_state()}
  def handle_in(msg, state) do
    try do
      do_handle_in(msg, state)
    rescue
      e ->
        disconnect_crash(msg, state, e)

        {:stop, :normal, state}
    end
  end

  defp do_handle_in({text, [opcode: :text]}, %{conn: conn} = state) do
    with {:ok, raw_json} <- decompress_message(text, conn),
         {:ok, wrapped_object} <- decode_message(raw_json, conn),
         {:ok, resp, new_conn} <- handle_command(wrapped_object, conn) do
      if resp != nil do
        {:reply, :ok, {:text, resp |> Jason.encode!()}, %{state | conn: new_conn}}
      else
        {:ok, state}
      end
    else
      {:json_error, error_message} ->
        {:reply, :ok,
         {:text,
          %{status: :failed, reason: :invalid_request, data: %{error: error_message}}
          |> Jason.encode!()}, state}

      {:error, err_resp, conn} ->
        {:reply, :ok, {:text, err_resp |> Jason.encode!()}, %{state | conn: conn}}
    end
  end

  # ignore any binary frame
  defp do_handle_in({_, [opcode: :binary]}, state) do
    {:ok, state}
  end

  # We currently don't have compression but if/when we do it will be tracked in the conn
  # so it goes here
  defp decompress_message(text, _conn) do
    {:ok, text}
  end

  @spec decode_message(String.t(), T.tachyon_conn()) :: {:ok, map()} | {:json_error, String.t()}
  defp decode_message(text, _conn) do
    case Jason.decode(text) do
      {:ok, msg} -> {:ok, msg}
      {:error, err} -> {:json_error, "Decode error: #{Exception.message(err)}"}
    end
  end

  @spec handle_command(map(), T.tachyon_conn()) ::
          {:ok, map() | nil, T.tachyon_conn()} | {:error, map(), T.tachyon_conn()}
  defp handle_command(request, conn) do
    message_id = request["messageId"]
    command_id = request["commandId"]

    # TODO: actually handle commands. Ditch the dispatch through a map and go
    # with the simple match on the command id
    case command_id do
      _ ->
        {:error,
         %{
           messageId: message_id,
           commandId: command_id,
           status: :failed,
           reason: :command_unimplemented
         }, conn}
    end
  end

  def handle_info(msg, state) do
    try do
      do_handle_info(msg, state)
    rescue
      e ->
        disconnect_crash(msg, state, e)

        {:stop, :normal, state}
    end
  end

  defp do_handle_info(:connect_to_client, state) do
    Account.cast_client(state.conn.userid, {:update_tcp_pid, self()})
    # TODO: handle errors
    case Handlers.System.Connected.handle(nil, state) do
      {:ok, data, state} ->
        resp = %{
          type: :event,
          status: :success,
          messageId: ULID.generate(),
          commandId: Handlers.System.Connected.command_id(),
          data: data
        }

        {:push, {:text, Jason.encode!(resp)}, state}

      {:error, reason, state} ->
        {:push,
         {:text,
          Jason.encode!(%{
            type: :event,
            status: :error,
            messageId: ULID.generate(),
            commandId: Handlers.System.Connected.command_id(),
            reason: reason
          })}, state}

      {:stop, _reason, state} ->
        {:stop, :normal, state}
    end
  end

  # Holdover from Spring stuff, discard message for now
  defp do_handle_info({:request_user_join_lobby, _}, state) do
    {:ok, state}
  end

  defp do_handle_info(%{channel: channel} = msg, state) do
    # First we find the module to handle this message, we have one module per channel
    module =
      case channel do
        "teiserver_lobby_host_message" <> _ ->
          MessageHandlers.LobbyHostMessageHandlers

        "teiserver_client_messages" <> _ ->
          MessageHandlers.ClientMessageHandlers

        "teiserver_lobby_updates" <> _ ->
          MessageHandlers.LobbyUpdateMessageHandlers

        "teiserver_lobby_chat" <> _ ->
          MessageHandlers.LobbyChatMessageHandlers

        _ ->
          raise "No handler for messages to channel #{msg.channel}"
      end

    # Now we get the module to try and handle it
    try do
      case module.handle(msg, state.conn) do
        nil ->
          {:ok, state}

        {:ok, new_conn} ->
          {:ok, %{state | conn: new_conn}}

        {:ok, resp, new_conn} ->
          {:reply, :ok, {:text, resp |> Jason.encode!()}, %{state | conn: new_conn}}
      end
    rescue
      e ->
        handle_error(e, __STACKTRACE__, state.conn)

        send(self(), :disconnect_on_error)

        {command, _, reason} =
          ErrorResponse.generate("Internal server error for internal channel #{channel}")

        response = %{
          "command" => command,
          "status" => "failure",
          "reason" => reason
        }

        {:reply, :ok, {:text, response |> Jason.encode!()}, state}
    end
  end

  # We have disconnect on error so we can later more easily make it so people can stay connected on error if needed for some reason
  defp do_handle_info(:disconnect_on_error, state) do
    {:stop, :disconnected, state}
  end

  defp do_handle_info(:disconnect, state) do
    {:stop, :disconnected, state}
  end

  defp do_handle_info(%{} = msg, state) do
    IO.puts("")
    IO.inspect(msg, label: "ws handle_info")
    IO.puts("")
    raise msg

    # Use this to not send anything
    {:ok, state}

    # This will send stuff
    # {:reply, :ok, {:binary, <<111>>}, state}
  end

  defp handle_error(error, stacktrace, _conn) do
    spawn(fn ->
      reraise error, stacktrace
    end)

    # Logger.error("EEEEE")

    # reraise error, stacktrace
  end

  defp disconnect_crash(msg, state, error) do
    userid = Kernel.get_in(state, [:conn, :userid])

    Logger.error(
      "tachyon crashed! #{inspect(error)} handling in #{inspect(msg)} with state #{inspect(state)}"
    )

    Teiserver.Client.disconnect(userid, "ws terminate - reason: #{inspect(error)}")
  end

  @spec terminate(any, any) :: :ok
  def terminate({:error, :closed}, %{conn: %{userid: userid}} = _state) do
    Teiserver.Client.disconnect(userid, "connection closed by client")
    :ok
  end

  def terminate(reason, %{conn: %{userid: userid}} = _state) do
    Teiserver.Client.disconnect(userid, "ws terminate - reason: #{inspect(reason)}")
    :ok
  end

  def terminate(_reason, _state) do
    :ok
  end

  defp login(%{user: _user, expires: _expires} = token, state) do
    response = Teiserver.CacheUser.login_from_token(token, state)

    case response do
      {:ok, user} ->
        {:ok, new_conn(user)}

      {:error, reason} ->
        {:error, reason}

      {:error, reason, _userid} ->
        {:error, reason}
    end
  end

  @spec new_conn(Teiserver.Account.User.t()) :: map()
  defp new_conn(user) do
    exempt_from_cmd_throttle = true

    %{
      # Client state
      userid: user.id,
      username: user.name,
      lobby_id: nil,
      lobby_host: false,
      party_id: nil,
      exempt_from_cmd_throttle: exempt_from_cmd_throttle,
      cmd_timestamps: [],
      error_handle: :raise,

      # Caching app configs
      flood_rate_limit_count:
        Config.get_site_config_cache("teiserver.Tachyon flood rate limit count"),
      floot_rate_window_size:
        Config.get_site_config_cache("teiserver.Tachyon flood rate window size")
    }
  end

  def handle_error(conn, {:missing_params, param}),
    do: Plug.Conn.send_resp(conn, 400, "Missing parameter(s): #{param}")

  def handle_error(conn, "missing_params: " <> param),
    do: Plug.Conn.send_resp(conn, 400, "Missing parameter(s): #{param}")

  def handle_error(conn, :no_user), do: Plug.Conn.send_resp(conn, 401, "Unauthorized")
  def handle_error(conn, :failed_login), do: Plug.Conn.send_resp(conn, 403, "Forbidden")
  def handle_error(conn, :rate_limit), do: Plug.Conn.send_resp(conn, 429, "Too many requests")

  def handle_error(conn, :unexpected_value),
    do: Plug.Conn.send_resp(conn, 500, "Internal server error")

  def handle_error(conn, stuff) do
    Logger.error("------------ HANDLING ERROR! #{inspect(stuff)}")
    Plug.Conn.send_resp(conn, 500, "Internal server error")
  end

  # Uncomment when we have an error we need to print out
  # def handle_error(conn, error) do
  #   raise "Unexpected error of #{inspect(error)}"

  #   Plug.Conn.send_resp(conn, 500, "Internal server error")
  # end
end
