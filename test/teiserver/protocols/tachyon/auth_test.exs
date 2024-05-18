defmodule Teiserver.Tachyon.AuthTest do
  use TeiserverWeb.ConnCase, async: false
  require Logger

  alias Teiserver.TeiserverTestLib
  alias TeiserverTest.Tachyon.WebsocketClient

  test "can connect" do
    %{query: query} = basic_setup()
    # this pattern match fails if connect! fails
    {:ok, ws} = WebsocketClient.connect!(make_url(query))
    WebsocketClient.disconnect(ws)
  end

  test "testing invalid token" do
    %{query: query} = basic_setup()
    url = make_url(%{query | token: "INVALID TOKEN"})
    {:error, %WebSockex.RequestError{code: code}} = WebsocketClient.connect(url)
    assert code == 401
  end

  test "testing missing app hash" do
    %{query: query} = basic_setup()
    url = make_url(Map.drop(query, [:application_hash]))
    {:error, %WebSockex.RequestError{code: code}} = WebsocketClient.connect(url)
    assert code == 400
  end

  test "testing missing app name" do
    %{query: query} = basic_setup()
    url = make_url(Map.drop(query, [:application_name]))
    {:error, %WebSockex.RequestError{code: code}} = WebsocketClient.connect(url)
    assert code == 400
  end

  test "testing missing app version" do
    %{query: query} = basic_setup()
    url = make_url(Map.drop(query, [:application_version]))
    {:error, %WebSockex.RequestError{code: code}} = WebsocketClient.connect(url)
    assert code == 400
  end

  defp basic_setup() do
    user = TeiserverTestLib.new_user()

    {:ok, token} =
      Teiserver.Account.create_user_token(%{
        user_id: user.id,
        value: Teiserver.Account.create_token_value(),
        ip: "127.0.0.1",
        user_agent: "test-agent",
        expires: Timex.now() |> Timex.shift(days: 1)
      })

    query = %{
      token: token.value,
      application_hash: "hash",
      application_name: "app_name",
      application_version: "version"
    }

    %{user: user, token: token, query: query}
  end

  defp make_url(query) do
    port = Application.get_env(:teiserver, TeiserverWeb.Endpoint)[:http][:port]
    "ws://127.0.0.1:#{port}/tachyon/websocket?#{URI.encode_query(query)}"
  end
end
