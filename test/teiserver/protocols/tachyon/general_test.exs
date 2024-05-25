defmodule Teiserver.Tachyon.GeneralTest do
  use TeiserverWeb.ConnCase, async: false
  require Logger
  alias Teiserver.TeiserverTestLib
  alias Teiserver.Tachyon.Schema
  alias TeiserverTest.Tachyon.{WebsocketClient, Helpers}

  setup do
    {:ok, client} = Helpers.start_connection()
    # swallow system connected message
    {:ok, _} = WebsocketClient.receive_message(client)
    {:ok, %{client: client}}
  end

  test "get error when sending invalid json", %{client: client} do
    :ok = WebsocketClient.send_message(client, ~s({"oops"))
    {:ok, resp} = WebsocketClient.receive_message(client)
    resp = Jason.decode!(resp)
    assert resp["status"] == "failed"
  end
end
