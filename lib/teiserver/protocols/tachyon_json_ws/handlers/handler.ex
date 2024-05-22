defmodule Teiserver.Tachyon.Handler do
  alias Teiserver.Tachyon.Types, as: T

  @callback command_id() :: String.t()

  # returns:
  # {:error, reason, new_state} -> reason to be sent to the client
  # {:stop, new_state} -> disconnect the client
  # {:ok, data, new state} -> data to send to the client
  @callback handle(data :: any(), state :: T.ws_state()) ::
              {:error, String.t(), T.ws_state()}
              | {:stop, any(), T.ws_state()}
              | {:ok, any(), T.ws_state()}
end
