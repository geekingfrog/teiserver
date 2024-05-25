defmodule Teiserver.Tachyon.AuthTest do
  use TeiserverWeb.ConnCase, async: false
  require Logger

  alias TeiserverTest.Tachyon.WebsocketClient
  alias TeiserverTest.Tachyon.Helpers

  test "can connect" do
    %{query: query} = Helpers.data_setup()
    # this pattern match fails if connect! fails
    {:ok, ws} = WebsocketClient.connect!(Helpers.make_url(query))
    WebsocketClient.disconnect(ws)
  end

  test "testing invalid token" do
    %{query: query} = Helpers.data_setup()
    url = Helpers.make_url(%{query | token: "INVALID TOKEN"})
    {:error, resp} = WebsocketClient.connect(url)
    assert resp.code == 401
  end

  test "testing missing app hash" do
    %{query: query} = Helpers.data_setup()
    url = Helpers.make_url(Map.drop(query, [:application_hash]))
    {:error, resp} = WebsocketClient.connect(url)
    assert resp.code == 400
  end

  test "testing missing app name" do
    %{query: query} = Helpers.data_setup()
    url = Helpers.make_url(Map.drop(query, [:application_name]))
    {:error, resp} = WebsocketClient.connect(url)
    assert resp.code == 400
  end

  test "testing missing app version" do
    %{query: query} = Helpers.data_setup()
    url = Helpers.make_url(Map.drop(query, [:application_version]))
    {:error, resp} = WebsocketClient.connect(url)
    assert resp.code == 400
  end
end
