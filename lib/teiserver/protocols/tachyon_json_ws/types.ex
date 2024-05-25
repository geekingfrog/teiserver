defmodule Teiserver.Tachyon.Types do
  alias Teiserver.Data.Types, as: T

  @type ws_state() :: %{params: tachyon_params(), conn: tachyon_conn()}

  @type tachyon_params() :: %{
          token: String.t(),
          application_hash: String.t(),
          application_name: String.t(),
          application_version: String.t()
        }
  @type tachyon_conn() :: %{
          userid: T.userid(),
          username: String.t(),
          lobby_id: T.lobby_id(),
          lobby_host: boolean(),
          party_id: T.party_id(),
          exempt_from_cmd_throttle: boolean(),
          cmd_timestamps: list(non_neg_integer()),
          error_handle: term(),
          status: :connected | :disconnected,
          flood_rate_limit_count: non_neg_integer() | nil,
          floot_rate_window_size: non_neg_integer() | nil
        }

end
