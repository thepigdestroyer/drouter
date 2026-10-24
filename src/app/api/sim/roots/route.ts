import { connection } from "next/server";
import { respond } from "@/lib/sim/http";
import { simRoots } from "@/lib/sim/roots";

export async function GET() {
  // Reads the hardware seed from the environment, so keep this out of build-time prerendering.
  await connection();
  return respond(simRoots);
}
