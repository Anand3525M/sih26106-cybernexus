"""
TraceMail Ingestion Module: RFC 5322 MIME Parser & Header Extractor
"""
from backend.ingestion.parser import parse_eml_bytes, parse_eml_file

__all__ = ["parse_eml_bytes", "parse_eml_file"]
