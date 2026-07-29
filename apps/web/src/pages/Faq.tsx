export function Faq() {
  return (
    <section className="card faq">
      <h2>How it works</h2>

      <details open>
        <summary>What happens when I share a secret?</summary>
        <p>
          Your browser generates a share code, derives an encryption key from it, and
          encrypts your secret <em>before anything leaves your device</em>. The
          encrypted copy is parked on our server so the receiver can pick it up any
          time. If you keep your tab open and the receiver opens the link while
          you're online, the secret instead travels <strong>directly between your
          two browsers</strong> — and the parked copy is deleted immediately.
        </p>
      </details>

      <details>
        <summary>What does the server see?</summary>
        <p>
          Ciphertext (encrypted bytes it cannot read), a random 8-character mailbox
          id used for routing, and hashed authentication tags. It never sees your
          secret, the five words of your code, or the encryption keys. The word part
          of the code never leaves your browser — even the share link keeps it in
          the <code>#fragment</code>, which browsers do not send to servers.
        </p>
      </details>

      <details>
        <summary>What's in the share code?</summary>
        <p>
          <code>XXXX-XXXX</code> is a random mailbox address. The five words are the
          actual key material — chosen from a 7,776-word list, giving about 65 bits
          of randomness. The encryption key is derived from those words using
          Argon2id, a deliberately slow function that makes guessing attacks
          impractical, with each mailbox salted separately.
        </p>
      </details>

      <details>
        <summary>What is "direct transfer only" mode?</summary>
        <p>
          By default we park an encrypted copy so delivery works even if you close
          your tab. In direct-only mode, <strong>nothing is uploaded at all</strong> —
          not even ciphertext. Your browser waits, and when the receiver arrives the
          secret moves straight between your devices. The trade-off: you must keep
          your tab open until they've received it, and if either side's network
          blocks peer-to-peer connections, delivery fails rather than falling back.
        </p>
      </details>

      <details>
        <summary>Can the secret be read twice?</summary>
        <p>
          No. The parked copy is destroyed the moment it is claimed (or delivered
          directly), five wrong code attempts burn it permanently, and it expires
          automatically — 24 hours by default, up to 7 days. A second person opening
          the same link sees only "already retrieved."
        </p>
      </details>

      <details>
        <summary>I pasted the wrong thing — can I undo?</summary>
        <p>
          Yes. As long as the secret hasn't been retrieved, the sender's screen has a
          <strong> "Destroy secret now"</strong> button that wipes the encrypted copy
          from the server immediately and makes the code useless.
        </p>
      </details>

      <details>
        <summary>Can you — the people running this service — read my secrets?</summary>
        <p>
          Not by design: keys are derived and encryption happens entirely in your
          browser, and the server stores only ciphertext. The honest caveat for any
          web-based tool: you are trusting the JavaScript we serve at the moment you
          use it. Our source is public for inspection at{" "}
          <a href="https://github.com/dovidcohen/secret-share" rel="noreferrer">
            github.com/dovidcohen/secret-share
          </a>
          . For the strongest posture, use direct-only mode between people who verify
          the code over a phone call.
        </p>
      </details>

      <details>
        <summary>Is there a command-line version?</summary>
        <p>
          Yes — <code>npx shareasecret</code> sends and receives with the same codes
          and the same encryption as this page, so either side can use the terminal
          while the other uses the browser:{" "}
          <code>cat id_ed25519 | npx shareasecret send --ttl 2h</code>. It pipes
          cleanly, emits JSON, and uses stable exit codes for scripting. See the{" "}
          <a href="/guides/cli">CLI guide</a> for full directions.
        </p>
      </details>

      <details>
        <summary>How big can a secret be, and what should I use this for?</summary>
        <p>
          Up to 10&nbsp;KB of text — SSH keys, API tokens, passwords, connection
          strings, recovery codes. It is not a file-sharing tool, and it is
          deliberately one-sender-to-one-receiver: read the code over a call or send
          the link over any channel you already trust.
        </p>
      </details>
    </section>
  );
}
