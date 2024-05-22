defmodule Teiserver.Tachyon.SystemTest do
  use TeiserverWeb.ConnCase, async: false
  require Logger
  alias Teiserver.TeiserverTestLib
  alias Teiserver.Tachyon.Schema
  alias TeiserverTest.Tachyon.{WebsocketClient, Helpers}

  test "receive system message upon connection" do
    {:ok, client} = Helpers.start_connection()
    {:ok, message} = WebsocketClient.receive_message(client, timeout: 50)
    resp = Jason.decode!(message)
    Schema.validate!(resp)
  end
end
