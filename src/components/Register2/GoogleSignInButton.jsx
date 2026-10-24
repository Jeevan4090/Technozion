import { useEffect, useRef, useState } from "react";

const GIS_SRC = "https://accounts.google.com/gsi/client";
const CLIENT_ID = process.env.REACT_APP_GOOGLE_CLIENT_ID;
const GOOGLE_BUTTON_HEIGHT = 40; // fixed by Google for size: "large"
const BUTTON_HEIGHT = 44; // matches the .ui-input height

const loadGoogleScript = () =>
  new Promise((resolve, reject) => {
    if (window.google?.accounts?.id) return resolve(window.google);
    let script = document.querySelector(`script[src="${GIS_SRC}"]`);
    if (!script) {
      script = document.createElement("script");
      script.src = GIS_SRC;
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }
    script.addEventListener("load", () => resolve(window.google), { once: true });
    script.addEventListener("error", () => reject(new Error("Could not load Google sign-in")), { once: true });
  });

// Renders Google's own "Sign in with Google" button and calls onCredential(idToken).
export default function GoogleSignInButton({ onCredential }) {
  const wrapper = useRef(null);
  const holder = useRef(null);
  const latest = useRef(onCredential);
  latest.current = onCredential;
  const [error, setError] = useState("");

  useEffect(() => {
    if (!CLIENT_ID || CLIENT_ID === "mock-client-id") {
      console.warn("Google sign-in is not configured with a valid client ID.");
    }
    let cancelled = false;
    loadGoogleScript()
      .then((google) => {
        if (cancelled || !holder.current) return;
        google.accounts.id.initialize({
          client_id: CLIENT_ID,
          callback: (response) => latest.current(response.credential),
        });

        const full = wrapper.current?.offsetWidth || 300;
        const width = Math.min(400, Math.max(200, full));

        try {
          google.accounts.id.renderButton(holder.current, {
            type: "standard",
            theme: "outline",
            size: "large",
            shape: "rectangular",
            text: "signin_with",
            width,
          });
          holder.current.style.width = `${width}px`;
          holder.current.style.transform = `scale(${full / width}, ${BUTTON_HEIGHT / GOOGLE_BUTTON_HEIGHT})`;
        } catch (e) {
          console.warn("Google button render failed.", e);
        }
      })
      .catch((err) => !cancelled && setError(err.message));
    return () => { cancelled = true; };
  }, []);

  return (
    <>
      <div
        ref={wrapper}
        className="group relative w-full rounded-lg"
        style={{ height: BUTTON_HEIGHT }}
      >
        {/* Visual layer */}
        <div
          aria-hidden="true"
          className="pointer-events-none flex h-full w-full items-center justify-center gap-3 rounded-lg
                     border border-[#2d2842] bg-[#1c192b] px-4 text-sm font-medium text-gray-200
                     shadow-sm transition-all duration-200
                     group-hover:border-[#9D71E8]/60 group-hover:bg-[#242136] group-hover:text-white
                     group-hover:shadow-[0_0_0_3px_rgba(157,113,232,0.12)]
                     group-active:scale-[0.99]
                     group-focus-within:border-[#9D71E8] group-focus-within:ring-2 group-focus-within:ring-[#9D71E8]/40"
        >
          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-white">
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
              <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
              <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
              <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
            </svg>
          </span>
          <span>Continue with Google</span>
        </div>

        {/* Google's real button, invisible, stretched on top to catch the click */}
        <div
          ref={holder}
          className="absolute left-0 top-0 z-10 cursor-pointer overflow-hidden rounded-lg"
          style={{ opacity: 0.01, height: GOOGLE_BUTTON_HEIGHT, transformOrigin: "top left" }}
        />
      </div>
      {error && <p className="mt-1.5 text-xs text-red-400">{error}</p>}
    </>
  );
}