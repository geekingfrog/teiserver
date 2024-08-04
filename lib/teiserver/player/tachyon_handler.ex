defmodule Teiserver.Player.TachyonHandler do
  @moduledoc """
  Player specific code to handle tachyon logins and actions
  """

  alias Teiserver.Tachyon.Handler
  alias Teiserver.Data.Types, as: T
  alias Teiserver.Player

  @behaviour Handler

  @type state :: %{user: T.user(), sess_mon_ref: reference()}

  @impl Handler
  def connect(conn) do
    # TODO: get the IP from request (somehow)
    ip = "127.0.0.1"
    lobby_client = conn.assigns[:token].application.uid
    user = conn.assigns[:token].owner

    case Teiserver.CacheUser.tachyon_login(user, ip, lobby_client) do
      {:ok, user} ->
        {:ok, %{user: user}}

      {:error, :rate_limited, msg} ->
        {:error, 429, msg}

      {:error, msg} ->
        {:error, 403, msg}
    end
  end

  @impl Handler
  @spec init(%{user: T.user()}) :: WebSock.handle_result()
  def init(initial_state) do
    # this is inside the process that maintain the connection
    {:ok, sess_mon_ref} = setup_session(initial_state.user.id)
    {:ok, Map.put(initial_state, :sess_mon_ref, sess_mon_ref)}
  end

  @impl Handler
  def handle_info({:DOWN, ref, :process, _sess_pid, _reason}, state)
      when state.sess_mon_ref == ref do
    # the associated session has died somehow, needs to restart it
    {:ok, sess_mon_ref} = setup_session(state.user.id)
    {:ok, %{state | sess_mon_ref: sess_mon_ref}}
  end

  def handle_info(_msg, state) do
    {:ok, state}
  end

  # Ensure a session is started for the given user id. Register both the session
  # and the connection. If a connection already exists, terminates it and
  # replace it in the player registry.
  defp setup_session(user_id) do
    case Player.SessionSupervisor.start_session(user_id) do
      {:ok, session_pid} ->
        register_and_monitor(user_id, session_pid)

      {:error, {:already_started, pid}} ->
        :ok = Player.Session.replace_connection(pid, self())
        register_and_monitor(user_id, pid)
    end
  end

  defp register_and_monitor(user_id, session_pid) do
    {:ok, _} = Player.Registry.register_and_kill_existing(user_id)

    # Need to monitor the session from the connection as well
    # in case it dies, the connection should restart it
    # this can typically happen when the session lives on another node than the
    # connection and the node stops
    sess_mon_ref = Process.monitor(session_pid)
    {:ok, sess_mon_ref}
  end
end
