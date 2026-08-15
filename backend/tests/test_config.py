from porygon_api.config import Settings


def test_database_url_escapes_password() -> None:
    settings = Settings(
        db_password="p@ss:word/with-specials",
        internal_api_token="x" * 32,
        operator_api_token="o" * 32,
    )
    rendered = settings.database_url.render_as_string(hide_password=False)
    assert "p%40ss%3Aword%2Fwith-specials" in rendered
    assert rendered.startswith("postgresql+psycopg://")
