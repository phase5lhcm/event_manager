from app.utils.common import setup_logging

def test_setup_logging_runs_without_error():
    """
    Ensure that the setup_logging function runs successfully without throwing errors.
    """
    try:
        setup_logging()
    except Exception as e:
        assert False, f"setup_logging raised an exception: {e}"
