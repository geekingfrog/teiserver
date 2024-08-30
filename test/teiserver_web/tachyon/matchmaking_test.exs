defmodule Teiserver.Matchmaking.MatchmakingTest do
  use TeiserverWeb.ConnCase
  alias Teiserver.Support.Tachyon

  describe "list" do
    setup {Tachyon, :setup_client}

    test "works", %{client: client} do
      resp = Tachyon.list_queues!(client)

      # convert into a set since the order must not impact test result
      expected_playlists =
        MapSet.new([
          %{
            "id" => "1v1",
            "name" => "Duel",
            "numOfTeams" => 2,
            "teamSize" => 1,
            "ranked" => true
          }
        ])

      assert MapSet.new(resp["data"]["playlists"]) == expected_playlists
    end
  end

  defp setup_queue(_context) do
    alias Teiserver.Matchmaking.QueueServer
    id = UUID.uuid4()

    {:ok, pid} =
      QueueServer.init_state(%{id: id, name: id, team_size: 1, team_count: 2})
      |> QueueServer.start_link()

    {:ok, queue_id: id, queue_pid: pid}
  end

  describe "joining queues" do
    setup [{Tachyon, :setup_client}, :setup_queue]

    test "works", %{client: client, queue_id: queue_id} do
      resp = Tachyon.join_queue!(client, queue_id)
      assert %{"status" => "success"} = resp
      resp = Tachyon.join_queue!(client, queue_id)
      assert %{"status" => "failed", "reason" => "already_queued"} = resp
    end
  end
end
