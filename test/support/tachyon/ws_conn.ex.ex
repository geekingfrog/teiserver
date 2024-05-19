defmodule TeiserverTest.Tachyon.WsConn do
  @moduledoc """
  Wrapper client to provide a synchronous interface to send and receive
  messages through websocket.
  """

  use WebSockex
  require Logger

  @doc """
  Connect to the given url.
  Can provide :ping_interval to send a ping frame every `ping_interval` ms
  """
  @spec connect(String.t(), pid, ping_interval: timeout() | nil) :: {:ok, pid}
  def connect(url, parent, opts \\ []) do
    state = %{
      parent: parent,
    }

    case WebSockex.start_link(url, __MODULE__, state) do
      {:ok, pid} ->
        if opts[:ping_interval] do
          :timer.send_interval(opts[:ping_interval], :ping)
        end

        {:ok, pid}

      err ->
        err
    end
  end

  def handle_frame({:text, msg}, %{parent: parent} = state) do
    send(parent, {:received_message, msg})
    {:ok, state}
  end

  def handle_frame(_frame, state) do
    # ignore binary frames
    {:ok, state}
  end

  def handle_cast({:send, msg}, state) do
    {:reply, {:text, msg}, state}
  end

  def handle_info(:ping, state) do
    {:reply, :ping, state}
  end
end
