defmodule TeiserverTest.Tachyon.WebsocketClient do
  @moduledoc """
  Wrapper client to provide a synchronous interface to send and receive
  messages through websocket.
  """

  use GenServer

  @enforce_keys [:pid, :default_timeout]
  defstruct [:pid, :default_timeout]

  @opaque client :: %__MODULE__{pid: pid, default_timeout: timeout()}

  @doc """
  Connect to the given url.
  Options:
    * :ping_interval to send a ping frame every `ping_interval` ms
    * :default_timeout how long receive_message should wait before any timeout
  """
  @spec connect!(String.t(), ping_interval: timeout() | nil, default_timeout: timeout() | nil) ::
          {:ok, client}
  def connect!(url, opts \\ []) do
    with {:ok, pid} <- GenServer.start_link(__MODULE__, [url: url] ++ opts) do
      client = %__MODULE__{pid: pid, default_timeout: Keyword.get(opts, :default_timeout, 10_000)}
      {:ok, client}
    end
  end

  @doc """
  Same as connect/2 but doesn't use start_link, so if the underlying websocket
  connection fails, it doesn't kill the caller
  """
  @spec connect(String.t(), ping_interval: timeout() | nil, default_timeout: timeout() | nil) ::
          {:ok, client}
  def connect(url, opts \\ []) do
    with {:ok, pid} <- GenServer.start(__MODULE__, [url: url] ++ opts) do
      client = %__MODULE__{pid: pid, default_timeout: Keyword.get(opts, :default_timeout, 10_000)}
      {:ok, client}
    end
  end

  @doc """
  Send a text message to the peer
  """
  @spec send_message(client, String.t(), :text | :binary | nil) :: :ok | {:error, reason :: term}
  def send_message(client, msg, type \\ :text) do
    if Process.alive?(client.pid) do
      GenServer.call(client.pid, {:send_message, msg, type})
    else
      {:error, :disconnected}
    end
  end

  @doc """
  Receive a text message coming from the peer.
  Returns immediately if a message has been buffered, otherwise, wait up to :timeout or 10s
  to disable timeout: set to :infinity
  """
  @spec receive_message(client, timeout: timeout()) ::
          {:ok, String.t()} | {:error, reason :: term}
  def receive_message(client, opts \\ []) do
    if Process.alive?(client.pid) do
      try do
        GenServer.call(
          client.pid,
          :receive_message,
          Keyword.get(opts, :timeout, client.default_timeout)
        )
      catch
        :exit, {:timeout, _} ->
          {:error, :timeout}
      end
    else
      {:error, :disconnected}
    end
  end

  @doc """
  Disconnect the socket, and empty any buffers.
  After this, the client should not be used anymore.
  """
  @spec disconnect(client) :: :ok
  def disconnect(client) do
    if Process.alive?(client.pid) do
      GenServer.cast(client.pid, :disconnect)
    end

    :ok
  end

  @impl true
  def init(opts \\ []) do
    # def connect(url, opts \\ []) do
    Process.flag(:trap_exit, true)
    url = Keyword.fetch!(opts, :url)

    with {:ok, pid} <-
           TeiserverTest.Tachyon.WsConn.connect(url, self(), ping_interval: opts[:ping_interval]) do
      state = %{
        received_messages: :queue.new(),
        awaiting_replies: :queue.new(),
        conn: pid,
        conn_state: :connected
      }

      {:ok, state}
    else
      {:error, err} -> {:stop, err}
    end
  end

  @impl true
  def handle_call({:send_message, _}, _from, %{conn_state: :disconnected} = state) do
    {:reply, {:error, :disconnected}, state}
  end

  @impl true
  def handle_call({:send_message, msg, type}, _from, %{conn: conn} = state) do
    :ok = WebSockex.send_frame(conn, {type, msg})
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(
        :receive_message,
        _from,
        %{conn_state: :disconnected, received_messages: buf} = state
      ) do
    case :queue.out(buf) do
      {:empty, _} ->
        {:reply, {:error, :disconnected}, state}

      {{:value, msg}, new_buf} ->
        {:reply, {:ok, msg}, %{state | received_messages: new_buf}}
    end
  end

  @impl true
  def handle_call(
        :receive_message,
        from,
        %{received_messages: buf, awaiting_replies: awaiting} = state
      ) do
    case :queue.out(buf) do
      {:empty, _} ->
        {:noreply, %{state | awaiting_replies: :queue.in(from, awaiting)}}

      {{:value, msg}, new_buf} ->
        {:reply, {:ok, msg}, %{state | received_messages: new_buf}}
    end
  end

  @impl true
  def handle_info(
        {:received_message, msg},
        %{received_messages: q, awaiting_replies: awaiting} = state
      ) do
    case :queue.out(awaiting) do
      {:empty, _} ->
        {:noreply, %{state | received_messages: :queue.in(msg, q)}}

      {{:value, from}, awaiting} ->
        :ok = GenServer.reply(from, {:ok, msg})
        {:noreply, %{state | awaiting_replies: awaiting}}
    end
  end

  def handle_info({:EXIT, conn_pid, _reason}, %{conn: conn, awaiting_replies: awaiting} = state)
      when conn == conn_pid do
    # immediately send a response to any waiting client
    :queue.fold(
      fn from, _acc ->
        GenServer.reply(from, {:error, :disconnected})
        nil
      end,
      nil,
      awaiting
    )

    {:noreply,
     %{
       state
       | conn_state: :disconnected,
         received_messages: :queue.new(),
         awaiting_replies: :queue.new()
     }}
  end

  @impl true
  def handle_cast(:disconnect, state) do
    final_state = %{
      state
      | conn_state: :disconnected,
        received_messages: :queue.new(),
        awaiting_replies: :queue.new()
    }

    {:stop, :normal, final_state}
  end
end
