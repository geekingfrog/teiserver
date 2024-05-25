defmodule TeiserverTest.Tachyon.Helpers do
  alias Teiserver.TeiserverTestLib
  alias TeiserverTest.Tachyon.WebsocketClient

  @doc """
  Given a map for the query parameter, returns the tachyon url to connect to
  """
  def make_url(query) do
    port = Application.get_env(:teiserver, TeiserverWeb.Endpoint)[:http][:port]
    "ws://127.0.0.1:#{port}/tachyon/websocket?#{URI.encode_query(query)}"
  end

  @doc """
  Creates a user in DB if not given already, create a token for this user and
  returns them alongside a query parameter map to be fed into make_url
  """
  @spec data_setup(nil | Map.t()) :: %{user: Map.t(), token: String.t(), query: Map.t()}
  def data_setup(user \\ nil) do
    user = if user, do: user, else: TeiserverTestLib.new_user()

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

  @doc """
  Establish a websocket connection for the given user (creates one if not provided)
  """
  @spec start_connection(nil | Map.t()) :: {:ok, WebsocketClient.client()} | {:error, String.t()}
  def start_connection(user \\ nil) do
    %{query: query} = data_setup(user)
    url = make_url(query)
    # set a short timeout. During test nothing should take long and it'll
    # avoid waiting long for a test to fail
    WebsocketClient.connect(url, default_timeout: 50)
  end
end
