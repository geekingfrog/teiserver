defmodule Teiserver.Autohost.Registry do
  @moduledoc """
  Registry used for websocket tachyon connections

  Note there's already a Teiserver.ClientRegistry which does more or less the
  same but for the spring protocol. However, with spring there are a few
  operations that requires to send messages to all connected clients.
  So unless there's a way to handle cross communication tachyon<->spring
  use a separate registry and keep clients separate.
  """

  alias Teiserver.Autohost.Autohost

  def start_link() do
    Horde.Registry.start_link(keys: :unique, name: __MODULE__)
  end

  @doc """
  how to reach a given autohost
  """
  @spec via_tuple(Autohost.id()) :: GenServer.name()
  def via_tuple(autohost_id) do
    {:via, Horde.Registry, {__MODULE__, autohost_id}}
  end

  @spec register(Autohost.id()) :: {:ok, pid()} | {:error, {:already_registered, pid()}}
  def register(autohost_id) do
    # this is needed because the process that handle the ws connection is spawned
    # by phoenix, so we can't spawn+register in the same step
    Horde.Registry.register(__MODULE__, via_tuple(autohost_id), autohost_id)
  end

  @spec lookup(Autohost.id()) :: pid() | nil
  def lookup(autohost_id) do
    case Horde.Registry.lookup(__MODULE__, via_tuple(autohost_id)) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  def child_spec(_) do
    Supervisor.child_spec(Horde.Registry,
      id: __MODULE__,
      start: {__MODULE__, :start_link, []}
    )
  end
end
