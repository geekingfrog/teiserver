defmodule Teiserver.Tachyon.Handlers.System.Connected do
  @moduledoc """
  https://github.com/beyond-all-reason/tachyon/blob/master/docs/schema/system.md#connected
  """
  alias Teiserver.Tachyon.Handler

  @behaviour Handler

  alias Teiserver.Tachyon.Types

  @impl Handler
  def command_id(), do: "system/connected"

  # @spec handle_connected(Types.tachyon_conn()) :: {:ok, any()}
  @impl Handler
  def handle(_, %{conn: conn} = state) do
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

    {:ok, resp, state}
  end
end
