import os
import sys
import json

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

os.environ["ENVIRONMENT"] = "test"

def export_openapi():
    try:
        from main import app
        openapi_schema = app.openapi()
        out_path = os.path.join(backend_dir, "openapi_baseline.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(openapi_schema, f, indent=2)
        print(f"[OK] Exported OpenAPI spec to {out_path} ({len(openapi_schema.get('paths', {}))} paths)")
    except Exception as e:
        print(f"[ERROR] Failed to export OpenAPI spec: {e}")

def export_schema_ddl():
    try:
        from database.models import Base
        from sqlalchemy.schema import CreateTable
        from database.database import engine
        
        out_path = os.path.join(backend_dir, "schema_baseline.sql")
        with open(out_path, "w", encoding="utf-8") as f:
            for table in Base.metadata.sorted_tables:
                ddl = str(CreateTable(table).compile(engine))
                f.write(ddl.strip() + ";\n\n")
        print(f"[OK] Exported DB DDL schema baseline to {out_path} ({len(Base.metadata.tables)} tables)")
    except Exception as e:
        print(f"[ERROR] Failed to export schema baseline: {e}")

if __name__ == "__main__":
    print("=== Generating Phase 0 Baseline Artifacts ===")
    export_openapi()
    export_schema_ddl()
