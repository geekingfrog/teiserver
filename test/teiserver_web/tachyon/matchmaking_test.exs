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

    test "with disconnections", %{token: token, client: client, queue_id: queue_id} do
      %{"status" => "success"} = Tachyon.join_queue!(client, queue_id)

      # clean disconnection removes user from queue
      Tachyon.disconnect!(client)
      client = Tachyon.connect(token)
      %{"status" => "success"} = Tachyon.join_queue!(client, queue_id)

      # A crash doesn't remove the player from the queue
      Tachyon.abrupt_disconnect!(client)
      client = Tachyon.connect(token)

      %{"status" => "failed", "reason" => "already_queued"} =
        Tachyon.join_queue!(client, queue_id)
    end
  end

  describe "leaving queues" do
    setup [{Tachyon, :setup_client}, :setup_queue]

    test "works", %{client: client, queue_id: queue_id} do
      assert %{"status" => "success"} = Tachyon.join_queue!(client, queue_id)
      assert %{"status" => "success"} = Tachyon.leave_queue!(client, queue_id)

      assert %{"status" => "failed", "reason" => "not_queued"} =
               Tachyon.leave_queue!(client, queue_id)
    end

    test "doesn't work on non existant queue", %{client: client} do
      assert %{"status" => "failed", "reason" => "not_queued"} =
               Tachyon.leave_queue!(client, "this is not a queue")
    end
  end
end
