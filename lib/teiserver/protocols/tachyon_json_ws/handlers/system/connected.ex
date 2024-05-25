defmodule Teiserver.Tachyon.Handlers.System.Connected do
  @moduledoc """
  https://github.com/beyond-all-reason/tachyon/blob/master/docs/schema/system.md#connected
  """
  alias Teiserver.Tachyon.Handler

  @behaviour Handler

  alias Teiserver.Tachyon.Types

  @impl Handler
  def command_id(), do: "system/connected"

  @impl Handler
  def handle(_, conn) do
    resp = %{
      userId: to_string(conn.userid),
      username: conn.username,
      displayName: "TODOMELON",
      avatarUrl: nil,
      clanId: nil,
      partyId: nil,
      # probably going to be removed
      scopes: [],
      countryCode: "TODOMELON",
      status: :menu,
      battleStatus: nil,
      friendIds: [],
      outgoingFriendRequestIds: [],
      incomingFriendRequestIds: [],
      ignoreIds: []
    }

    {:ok, resp, conn}
  end
end
