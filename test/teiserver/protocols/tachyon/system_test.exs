defmodule Teiserver.Tachyon.SystemTest do
  use TeiserverWeb.ConnCase, async: false
  require Logger
  alias Teiserver.Tachyon.Schema
  alias TeiserverTest.Tachyon.{WebsocketClient, Helpers}

  test "receive system message upon connection" do
    {:ok, client} = Helpers.start_connection()
    {:ok, message} = WebsocketClient.receive_message(client)
    resp = Jason.decode!(message)
    Schema.validate!(resp)
  end

  test "disconnect request" do
    {:ok, client} = Helpers.start_connection()
    {:ok, _msg} = WebsocketClient.receive_message(client)
    req = %{messageId: "123", commandId: "system/disconnect", data: %{reason: "kthxbye"}}
    :ok = WebsocketClient.send_message(client, Jason.encode!(req))
    {:ok, resp} = Helpers.receive_json(client)

    assert resp == %{
             "commandId" => "system/disconnect",
             "messageId" => "123",
             "status" => "success"
           }

    # the connection should now be closed
    resp = WebsocketClient.send_message(client, "nope")
    assert resp == {:error, :disconnected}
  end
end
