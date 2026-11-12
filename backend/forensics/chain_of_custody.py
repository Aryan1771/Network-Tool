from datetime import datetime
from backend.database.db import query_db, execute_db

class ChainOfCustodyService:
    """
    Forensic Chain of Custody Management Service.
    Enforces append-only immutable-style audit logging adhering to ISO/IEC 27037 standards.
    Scope: Designed to support evidence handling and audit workflows.
    """

    @staticmethod
    def generate_log_id():
        row = query_db("SELECT COUNT(*) as count FROM chain_of_custody", one=True)
        count = (row["count"] if row else 0) + 1
        year = datetime.now().year
        return f"COC-{year}-{count:05d}"

    @classmethod
    def record_action(cls, evidence_id, action, actor, actor_role, file_hash, description, verification_result=None, notes=None):
        """
        Appends an immutable audit log entry.
        """
        log_id = cls.generate_log_id()
        execute_db("""
            INSERT INTO chain_of_custody (
                log_id, evidence_id, action, actor, actor_role,
                file_hash, verification_result, description, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_id, evidence_id, action, actor, actor_role,
            file_hash, verification_result, description, notes
        ))
        return log_id

    @classmethod
    def get_audit_trail(cls, evidence_id=None, action_filter=None, search=None):
        """
        Retrieves chronological chain-of-custody audit logs with optional filters.
        """
        conditions = []
        params = []

        if evidence_id:
            conditions.append("evidence_id = ?")
            params.append(evidence_id)

        if action_filter and action_filter != "ALL":
            conditions.append("action = ?")
            params.append(action_filter)

        if search:
            conditions.append("(log_id LIKE ? OR description LIKE ? OR actor LIKE ? OR file_hash LIKE ?)")
            pattern = f"%{search}%"
            params.extend([pattern, pattern, pattern, pattern])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT c.*, e.original_filename, e.stored_filename
            FROM chain_of_custody c
            LEFT JOIN evidence e ON c.evidence_id = e.id
            {where_clause}
            ORDER BY c.id DESC
        """
        return query_db(query, params)
