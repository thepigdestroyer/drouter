import { Console } from "@/components/console";
import { AuthGate } from "@/components/auth/auth-gate";
import { AuthPill } from "@/components/auth-pill";
import { SpecimenFooter, SpecimenHeader } from "@/components/specimen-chrome";
import { APP_PAGE_COPY } from "@/components/landing/landing-copy";

export default function AppChatPage() {
  return (
    <div className="min-h-screen flex flex-col overflow-x-hidden text-ink">
      <SpecimenHeader activePath="/app" rightSlot={<AuthPill />} />

      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-4 py-6 sm:px-6 sm:py-10"
      >
        <section aria-labelledby="app-chat-heading" className="max-w-[70ch]">
          <div className="ep-label">{APP_PAGE_COPY.eyebrow}</div>
          <h1
            id="app-chat-heading"
            className="ep-display mt-1.5 text-2xl sm:text-3xl"
          >
            {APP_PAGE_COPY.heading}
          </h1>
        </section>

        <section aria-label="Private chat console">
          <AuthGate>
            <Console />
          </AuthGate>
        </section>
      </main>

      <SpecimenFooter />
    </div>
  );
}
