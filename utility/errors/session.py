class SessionUserNotFoundError(Exception):
    def __init__(self, session_id=None):
        self.session_id = session_id
        message = "Session was valid but no matching user could be found."
        if session_id:
            message = f"Session {session_id!r} was valid but no matching user could be found."
        super().__init__(message)
