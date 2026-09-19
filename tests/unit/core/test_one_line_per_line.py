"""Every pipeline line was written to stdout twice.

The `maljan` logger installs a handler of its own so a CLI caller with no
logging set up still sees something. The API and the worker install a handler
on the root logger, and the `maljan` logger propagates to it, so once either
of them has started every line is emitted twice — once plain, once through the
root formatter. Measured in a live run: 3 306 coloured lines in the worker
log, each unique message appearing exactly twice.

The handler that exists for the caller who has none is the one to drop once
somebody else is formatting.

`arq` has the same shape and had the same fault. Its CLI is the worker's entry
point and configures logging on the way in, so by the time the application
configures its own there is already a handler on the `arq` logger and it still
propagates: a worker log carrying 19 lines with the `[arq.worker]` prefix
against 21 bare `HH:MM:SS: ` ones is the same line counted twice. The hand-over
is the same hand-over.
"""

from __future__ import annotations

import logging

from maljan.core.logger import hand_over_to_root, setup_logger


class TestTheApplicationLoggerWritesOnce:
    def test_a_logger_nobody_configured_keeps_its_own_handler(self) -> None:
        """A CLI caller has no root handler, so this one is all there is."""
        name = "maljan_test_alone"
        logging.getLogger(name).handlers.clear()
        assert len(setup_logger(name).handlers) == 1

    def test_the_hand_over_leaves_the_root_handler_alone_with_it(self) -> None:
        name = "maljan_test_handover"
        logging.getLogger(name).handlers.clear()
        configured = setup_logger(name)
        assert hand_over_to_root(name) is True
        assert configured.handlers == []
        assert configured.propagate is True

    def test_handing_over_twice_is_not_an_error(self) -> None:
        name = "maljan_test_twice"
        logging.getLogger(name).handlers.clear()
        setup_logger(name)
        assert hand_over_to_root(name) is True
        assert hand_over_to_root(name) is False

    def test_a_handler_somebody_else_added_is_not_taken_away(self) -> None:
        """Only the one this module installed is this module's to remove."""
        name = "maljan_test_foreign"
        logger = logging.getLogger(name)
        logger.handlers.clear()
        setup_logger(name)
        mine = logging.NullHandler()
        logger.addHandler(mine)
        hand_over_to_root(name)
        assert logger.handlers == [mine]
        logger.handlers.clear()

    def test_the_api_hands_the_application_logger_over_when_it_configures_logging(self) -> None:
        from app.logging_config import setup_logging

        maljan = logging.getLogger("maljan")
        maljan.handlers.clear()
        setup_logger("maljan")
        assert maljan.handlers

        root = logging.getLogger()
        kept = list(root.handlers)
        try:
            setup_logging()
            assert maljan.handlers == [], "the root handler formats these lines now"
            assert len(root.handlers) == 1
            record = logging.LogRecord("maljan", logging.INFO, __file__, 1, "once", None, None)
            assert sum(handler.level <= record.levelno for handler in root.handlers) == 1
        finally:
            root.handlers.clear()
            root.handlers.extend(kept)
            setup_logger("maljan")


def _arq_configured() -> logging.Logger:
    """The `arq` logger as its own CLI leaves it, handler and all."""
    import logging.config

    from arq.logs import default_log_config

    logging.config.dictConfig(default_log_config(False))
    return logging.getLogger("arq")


class TestTheWorkerRunnerLoggerWritesOnce:
    def test_its_own_cli_leaves_a_handler_behind(self) -> None:
        """The fault this is about, stated as the fact it rests on."""
        arq = _arq_configured()
        try:
            assert [handler.get_name() for handler in arq.handlers] == ["arq.standard"]
            assert arq.propagate is True
        finally:
            arq.handlers.clear()

    def test_the_hand_over_leaves_the_root_handler_alone_with_it(self) -> None:
        from app.logging_config import hand_arq_over_to_root

        arq = _arq_configured()
        try:
            assert hand_arq_over_to_root() is True
            assert arq.handlers == []
            assert arq.propagate is True
            assert hand_arq_over_to_root() is False
        finally:
            arq.handlers.clear()

    def test_a_handler_somebody_else_added_is_not_taken_away(self) -> None:
        from app.logging_config import hand_arq_over_to_root

        arq = _arq_configured()
        mine = logging.NullHandler()
        arq.addHandler(mine)
        try:
            hand_arq_over_to_root()
            assert arq.handlers == [mine]
        finally:
            arq.handlers.clear()

    def test_one_line_is_written_once_in_the_application_format(self) -> None:
        from app.logging_config import setup_logging

        arq = _arq_configured()
        root = logging.getLogger()
        kept = list(root.handlers)
        try:
            setup_logging()
            assert arq.handlers == [], "the root handler formats these lines now"
            record = logging.LogRecord("arq.worker", logging.INFO, __file__, 1, "once", None, None)
            writers = [
                handler
                for handler in (*arq.handlers, *root.handlers)
                if handler.level <= record.levelno
            ]
            assert len(writers) == 1
            assert "arq.worker" in writers[0].format(record)
        finally:
            arq.handlers.clear()
            root.handlers.clear()
            root.handlers.extend(kept)
            setup_logger("maljan")
