defmodule Teiserver.Tachyon.Handler do
  alias Teiserver.Tachyon.Types, as: T

  @callback command_id() :: String.t()

  # returns:
  # {:error, reason, new_state} -> reason to be sent to the client
  # {:stop, new_state} -> disconnect the client
  # {:ok, data, new state} -> data to send to the client
  @callback handle(data :: any(), state :: T.tachyon_conn()) ::
              {:error, String.t(), T.tachyon_conn()}
              | {:stop, any(), T.tachyon_conn()}
              | {:ok, any(), T.tachyon_conn()}
end
