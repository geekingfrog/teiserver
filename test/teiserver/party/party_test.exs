defmodule Teiserver.Party.PartyTest do
  use Teiserver.DataCase

  @moduletag :tachyon

  alias Teiserver.Party
  alias Teiserver.Support.Polling

  test "create party" do
    {:ok, _} = Horde.Registry.register(Teiserver.Player.SessionRegistry, 123, nil)
    assert {:ok, party_id, _pid} = Party.create_party(123)
    Polling.poll_until_some(fn -> Party.lookup(party_id) end)
  end

  describe "snapshot" do
    setup [:setup_config]

    test "restore party from snapshot" do
    end
  end

  def setup_config(_) do
    Teiserver.Tachyon.enable_state_restoration()
    ExUnit.Callbacks.on_exit(fn -> Teiserver.Tachyon.disable_state_restoration() end)
  end
end
