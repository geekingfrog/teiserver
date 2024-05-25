defmodule Teiserver.Tachyon.Handlers.System.DisconnectRequest do
  @moduledoc """
  https://github.com/beyond-all-reason/tachyon/blob/master/docs/schema/system.md
  """
  alias Teiserver.Tachyon.Handler

  @behaviour Handler

  alias Teiserver.Tachyon.Types

  @impl Handler
  def command_id(), do: "system/disconnect"

  @impl Handler
  def handle(_, conn) do
    Teiserver.Client.disconnect(conn.userid, "WS disconnect request")
    {:stop, nil, conn}
  end
end
