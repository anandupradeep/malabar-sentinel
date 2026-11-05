"""
INTEGRATION PATCH — server/main.py
====================================
Apply these three changes to main.py to wire in scan routes.

1. ADD imports at the top (after the existing command_queue imports):

   from scan_routes import router as scan_router, attach_scan_routes
   from scan_manager import init_scan_tables, log_event as tl_log_event

2. MODIFY the lifespan function (add two lines after await db.initialize()):

   async def lifespan(app: FastAPI):
       await db.initialize()
       await init_scan_tables(db)                          # ← ADD
       attach_scan_routes(db, _issue_command, verify_api_key)  # ← ADD
       asyncio.create_task(_housekeeping())
       logger.info("Malabar Sentinel v2.0 ready")
       yield

3. ADD router include (after the app = FastAPI(...) block, near other includes):

   app.include_router(scan_router)

4. OPTIONAL — hook timeline logging into the command-response endpoint.
   In the command_response() function, after the result is stored, add:

       # Log block/unblock commands to timeline
       cmd = data.get("command", "")
       ep  = data.get("endpoint_id", "")
       if cmd in ("block_ip", "unblock_ip", "block_url", "unblock_url"):
           import asyncio
           params = data.get("parameters", {})
           target = params.get("ip") or params.get("url", "")
           sev    = "high" if "block" in cmd and "un" not in cmd else "low"
           asyncio.create_task(
               tl_log_event(db, ep, "block",
                            f"{cmd.replace('_',' ').title()}: {target}",
                            severity=sev)
           )

NOTE: _issue_command is defined before lifespan in main.py so it is
available when attach_scan_routes is called in lifespan — no forward-
reference issues.
"""
