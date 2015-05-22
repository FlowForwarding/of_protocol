-define(DEBUG(Msg),
        lager:debug(Msg)).
-define(DEBUG(Msg, Args),
        lager:debug(Msg, Args)).

-define(INFO(Msg),
        lager:info(Msg)).
-define(INFO(Msg, Args),
        lager:info(Msg, Args)).

-define(WARNING(Msg),
        lager:warning(Msg)).
-define(WARNING(Msg, Args),
        lager:warning(Msg, Args)).

-define(ERROR(Msg),
        lager:error(Msg)).
-define(ERROR(Msg, Args),
        lager:error(Msg, Args)).
