import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Toaster } from "@/components/ui/sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ArrowLeft,
  ImageIcon,
  Loader2,
  Lock,
  LockOpen,
  LogOut,
  Menu,
  MessageSquare,
  Search,
  Send,
  Shield,
  Trash2,
  Users,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import type { Message } from "./backend.d";
import {
  b64ToBuf,
  bufToB64,
  decryptBytes,
  decryptMessage,
  encryptBytes,
  encryptMessage,
  exportPublicKey,
  getOrCreateKeyPair,
  importPublicKey,
} from "./crypto";
import { useActor } from "./hooks/useActor";

// ── helpers ──────────────────────────────────────────────────────────────────
async function hashPassword(password: string): Promise<string> {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(password));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getInitials(name: string) {
  return name.slice(0, 2).toUpperCase();
}

const AVATAR_COLORS = [
  "oklch(0.55 0.17 255)",
  "oklch(0.60 0.17 150)",
  "oklch(0.60 0.20 30)",
  "oklch(0.60 0.18 320)",
  "oklch(0.60 0.18 200)",
  "oklch(0.60 0.19 60)",
];

function avatarColor(name: string) {
  let hash = 0;
  for (let i = 0; i < name.length; i++)
    hash = (hash * 31 + name.charCodeAt(i)) | 0;
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}

function formatTime(ts: bigint) {
  const ms = Number(ts) / 1_000_000;
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function isEncryptedEnvelope(content: string): boolean {
  try {
    const obj = JSON.parse(content);
    return (
      !!obj.ciphertext && !!obj.iv && !!obj.senderKey && !!obj.recipientKey
    );
  } catch {
    return false;
  }
}

interface ImageEnvelope {
  type: "image";
  data: string;
  mimeType: string;
  iv: string;
  senderKey: string;
  recipientKey: string;
}

function parseImageEnvelope(content: string): ImageEnvelope | null {
  try {
    const obj = JSON.parse(content);
    if (
      obj.type === "image" &&
      obj.data &&
      obj.iv &&
      obj.senderKey &&
      obj.recipientKey
    ) {
      return obj as ImageEnvelope;
    }
    return null;
  } catch {
    return null;
  }
}

function renderTextWithLinks(text: string): React.ReactNode[] {
  const urlRegex = /https?:\/\/[^\s]+/g;
  const result: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  urlRegex.lastIndex = 0;
  // biome-ignore lint/suspicious/noAssignInExpressions: regex loop pattern
  while ((match = urlRegex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      result.push(text.slice(lastIndex, match.index));
    }
    const url = match[0];
    result.push(
      <a
        key={match.index}
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        className="underline break-all"
        style={{ color: "oklch(0.72 0.15 240)" }}
        onClick={(e) => e.stopPropagation()}
      >
        {url}
      </a>,
    );
    lastIndex = urlRegex.lastIndex;
  }
  if (lastIndex < text.length) {
    result.push(text.slice(lastIndex));
  }
  return result;
}

const MAX_IMAGE_SIZE = 7 * 1024 * 1024;
const ALLOWED_IMAGE_TYPES = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
];

// 24 hours in nanoseconds
const TWENTY_FOUR_HOURS_NS = BigInt(24 * 60 * 60 * 1000) * BigInt(1_000_000);

function isMessageExpired(timestamp: bigint): boolean {
  const nowNs = BigInt(Date.now()) * BigInt(1_000_000);
  return nowNs - timestamp > TWENTY_FOUR_HOURS_NS;
}

// ── Long-press hook ───────────────────────────────────────────────────────────
function useLongPress(onLongPress: () => void, delay = 600) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const didLongPress = useRef(false);

  const start = useCallback(() => {
    didLongPress.current = false;
    timerRef.current = setTimeout(() => {
      didLongPress.current = true;
      onLongPress();
    }, delay);
  }, [onLongPress, delay]);

  const cancel = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  // Prevent click from firing after long-press
  const preventClick = useCallback((e: React.MouseEvent | React.TouchEvent) => {
    if (didLongPress.current) {
      e.preventDefault();
      e.stopPropagation();
    }
  }, []);

  return {
    onMouseDown: start,
    onMouseUp: cancel,
    onMouseLeave: cancel,
    onTouchStart: start,
    onTouchEnd: cancel,
    onClick: preventClick,
  };
}

// ── Auth Screen ───────────────────────────────────────────────────────────────
function AuthScreen({
  onLogin,
}: { onLogin: (username: string, hash: string) => void }) {
  const { actor, isFetching } = useActor();
  const [tab, setTab] = useState<"login" | "signup">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!actor) {
        toast.error(
          "App is still connecting. Please wait a moment and try again.",
        );
        return;
      }
      if (isFetching) {
        toast.error("Connecting to server, please wait…");
        return;
      }
      const trimmedUser = username.trim();
      if (!trimmedUser || !password) {
        toast.error("Please fill in all fields");
        return;
      }
      setLoading(true);
      try {
        const hash = await hashPassword(password);
        if (tab === "signup") {
          try {
            await actor.registerUser(trimmedUser, hash);
          } catch (regErr) {
            const msg = String(regErr);
            if (
              msg.includes("already taken") ||
              msg.includes("already exists")
            ) {
              toast.error(
                "Username already taken. Please choose a different one.",
              );
            } else {
              toast.error(
                `Sign up failed: ${msg.split("\n")[0].slice(0, 120)}`,
              );
            }
            return;
          }
          toast.success("Account created! Logging you in…");
        }
        let ok = false;
        try {
          ok = await actor.loginUser(trimmedUser, hash);
        } catch (loginErr) {
          const msg = String(loginErr);
          toast.error(`Login failed: ${msg.split("\n")[0].slice(0, 120)}`);
          return;
        }
        if (ok) {
          localStorage.setItem("cc_user", trimmedUser);
          onLogin(trimmedUser, hash);
        } else {
          toast.error("Invalid username or password.");
        }
      } catch (err) {
        const msg = String(err);
        toast.error(
          msg.length > 10
            ? msg.split("\n")[0].slice(0, 150)
            : "Something went wrong. Please try again.",
        );
        console.error(err);
      } finally {
        setLoading(false);
      }
    },
    [actor, isFetching, tab, username, password, onLogin],
  );

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse 80% 60% at 50% 0%, oklch(0.22 0.055 255 / 0.35) 0%, transparent 70%)",
        }}
      />

      <header className="bg-chat-nav border-b border-border sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div
              className="w-7 h-7 rounded-md flex items-center justify-center"
              style={{ background: "oklch(0.55 0.17 255)" }}
            >
              <Lock className="w-4 h-4 text-white" />
            </div>
            <span className="font-bold text-foreground tracking-tight">
              CipherChat
            </span>
          </div>
          <nav className="hidden md:flex items-center gap-6 text-sm text-chat-meta">
            <button
              type="button"
              className="hover:text-foreground transition-colors"
            >
              Features
            </button>
            <button
              type="button"
              className="hover:text-foreground transition-colors"
            >
              Pricing
            </button>
            <button
              type="button"
              className="hover:text-foreground transition-colors"
            >
              About
            </button>
          </nav>
        </div>
      </header>

      <div className="relative flex-1 flex flex-col items-center justify-center px-4 py-16">
        <div className="flex flex-wrap justify-center gap-2 mb-8 animate-fade-up">
          {[
            { icon: Shield, label: "End-to-End Encrypted" },
            { icon: Users, label: "Global User List" },
            { icon: Zap, label: "Instant Messaging" },
          ].map(({ icon: Icon, label }) => (
            <div
              key={label}
              className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-muted text-chat-meta border border-border"
            >
              <Icon
                className="w-3 h-3"
                style={{ color: "oklch(0.55 0.17 255)" }}
              />
              {label}
            </div>
          ))}
        </div>

        <h1
          className="text-4xl md:text-5xl font-bold text-foreground text-center mb-3 animate-fade-up"
          style={{ animationDelay: "0.05s" }}
        >
          Secure by design.
        </h1>
        <p
          className="text-chat-meta text-center max-w-md mb-10 animate-fade-up"
          style={{ animationDelay: "0.1s" }}
        >
          Private conversations, encrypted before they leave your device. No one
          else can read your messages.
        </p>

        <div
          className="w-full max-w-sm rounded-2xl border border-border shadow-card animate-fade-up"
          style={{
            background: "oklch(0.22 0.03 235)",
            animationDelay: "0.15s",
          }}
        >
          <Tabs
            value={tab}
            onValueChange={(v) => setTab(v as "login" | "signup")}
            className="w-full"
          >
            <TabsList
              className="w-full rounded-t-2xl rounded-b-none h-12 bg-muted/50 border-b border-border"
              data-ocid="auth.tab"
            >
              <TabsTrigger
                value="login"
                className="flex-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary"
                data-ocid="auth.login.tab"
              >
                Log in
              </TabsTrigger>
              <TabsTrigger
                value="signup"
                className="flex-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary"
                data-ocid="auth.signup.tab"
              >
                Sign up
              </TabsTrigger>
            </TabsList>

            {(["login", "signup"] as const).map((t) => (
              <TabsContent key={t} value={t} className="p-6">
                <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                  <div className="flex flex-col gap-1.5">
                    <label
                      htmlFor={`${t}-username`}
                      className="text-xs font-medium text-chat-meta"
                    >
                      Username
                    </label>
                    <Input
                      id={`${t}-username`}
                      data-ocid="auth.username.input"
                      placeholder="your_username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username"
                      className="bg-input border-border text-foreground placeholder:text-muted-foreground focus-visible:ring-primary"
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label
                      htmlFor={`${t}-password`}
                      className="text-xs font-medium text-chat-meta"
                    >
                      Password
                    </label>
                    <Input
                      id={`${t}-password`}
                      data-ocid="auth.password.input"
                      type="password"
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete={
                        t === "signup" ? "new-password" : "current-password"
                      }
                      className="bg-input border-border text-foreground placeholder:text-muted-foreground focus-visible:ring-primary"
                    />
                  </div>
                  <Button
                    data-ocid="auth.submit_button"
                    type="submit"
                    disabled={loading || isFetching}
                    className="w-full h-10 font-semibold mt-1"
                    style={{
                      background: "oklch(0.55 0.17 255)",
                      color: "white",
                    }}
                  >
                    {loading || isFetching ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />{" "}
                        {isFetching
                          ? "Connecting…"
                          : t === "login"
                            ? "Logging in…"
                            : "Creating account…"}
                      </>
                    ) : t === "login" ? (
                      "Log in"
                    ) : (
                      "Create account"
                    )}
                  </Button>
                </form>
              </TabsContent>
            ))}
          </Tabs>
        </div>
      </div>

      <footer className="text-center text-xs text-chat-meta py-6">
        © {new Date().getFullYear()}. Built with{" "}
        <span style={{ color: "oklch(0.72 0.17 30)" }}>♥</span> using{" "}
        <a
          href={`https://caffeine.ai?utm_source=caffeine-footer&utm_medium=referral&utm_content=${encodeURIComponent(window.location.hostname)}`}
          className="hover:text-foreground transition-colors"
          target="_blank"
          rel="noopener noreferrer"
        >
          caffeine.ai
        </a>
      </footer>
    </div>
  );
}

// ── Chat App ──────────────────────────────────────────────────────────────────
function ChatApp({
  currentUser,
  onLogout,
  passwordHash,
}: { currentUser: string; onLogout: () => void; passwordHash: string }) {
  const { actor, isFetching } = useActor();
  const [users, setUsers] = useState<string[]>([]);
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [messages, setMessages] = useState<Message[]>([]);
  const [messageText, setMessageText] = useState("");
  const [sending, setSending] = useState(false);
  const [search, setSearch] = useState("");
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [encryptingImage, setEncryptingImage] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Unsend context menu
  const [unsendMenuId, setUnsendMenuId] = useState<string | null>(null);

  // Crypto state
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const publicKeyRef = useRef<CryptoKey | null>(null);
  const [cryptoReady, setCryptoReady] = useState(false);

  const [decryptedMessages, setDecryptedMessages] = useState<
    Map<string, string | null>
  >(new Map());
  const [decryptingIds, setDecryptingIds] = useState<Set<string>>(new Set());

  const [decryptedImages, setDecryptedImages] = useState<
    Map<string, string | "error">
  >(new Map());
  const [decryptingImageIds, setDecryptingImageIds] = useState<Set<string>>(
    new Set(),
  );
  const imageObjectUrlsRef = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    const urls = imageObjectUrlsRef.current;
    return () => {
      for (const url of urls.values()) URL.revokeObjectURL(url);
    };
  }, []);

  // Close unsend menu when clicking outside
  useEffect(() => {
    if (!unsendMenuId) return;
    const handleClick = () => setUnsendMenuId(null);
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("touchstart", handleClick);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("touchstart", handleClick);
    };
  }, [unsendMenuId]);

  // Initialise E2EE keys
  useEffect(() => {
    if (!actor || isFetching) return;
    let cancelled = false;
    async function initCrypto() {
      try {
        const pair = await getOrCreateKeyPair(currentUser);
        if (cancelled) return;
        privateKeyRef.current = pair.privateKey;
        publicKeyRef.current = pair.publicKey;
        const pubB64 = await exportPublicKey(pair.publicKey);
        if (cancelled) return;
        await (actor as any).storePublicKey(currentUser, passwordHash, pubB64);
        setCryptoReady(true);
      } catch (err) {
        console.error("Crypto init failed", err);
        toast.error("Encryption setup failed. Messages may be unencrypted.");
        setCryptoReady(true);
      }
    }
    initCrypto();
    return () => {
      cancelled = true;
    };
  }, [actor, isFetching, currentUser, passwordHash]);

  // Fetch users
  const fetchUsers = useCallback(async () => {
    if (!actor || isFetching) return;
    try {
      const all = await actor.listUsers();
      setUsers(all.filter((u) => u !== currentUser));
    } catch (err) {
      console.error("Failed to fetch users", err);
    } finally {
      setLoadingUsers(false);
    }
  }, [actor, isFetching, currentUser]);

  // Fetch conversation (with frontend 24h filter)
  const fetchMessages = useCallback(async () => {
    if (!actor || !selectedUser) return;
    try {
      const msgs = await actor.getConversation(currentUser, selectedUser);
      const sorted = [...msgs].sort((a, b) =>
        a.timestamp < b.timestamp ? -1 : 1,
      );
      // Frontend safety filter: drop any messages older than 24h
      const fresh = sorted.filter((m) => !isMessageExpired(m.timestamp));
      setMessages(fresh);
    } catch (err) {
      console.error("Failed to fetch messages", err);
    }
  }, [actor, currentUser, selectedUser]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);
  // When conversation opens: purge expired messages (fire and forget)
  useEffect(() => {
    if (!actor || !selectedUser) return;
    (actor as any)
      .purgeExpiredMessages()
      .catch((err) => console.warn("purgeExpiredMessages failed", err));
  }, [actor, selectedUser]);

  // Poll messages every 3s
  useEffect(() => {
    if (!selectedUser) return;
    setLoadingMessages(true);
    fetchMessages().finally(() => setLoadingMessages(false));
    const id = setInterval(fetchMessages, 3000);
    return () => clearInterval(id);
  }, [selectedUser, fetchMessages]);

  // Decrypt TEXT messages
  // biome-ignore lint/correctness/useExhaustiveDependencies: decrypt when messages array changes
  useEffect(() => {
    if (!privateKeyRef.current || messages.length === 0) return;
    const privateKey = privateKeyRef.current;
    const newIds: string[] = [];
    for (const msg of messages) {
      if (msg.isImage) continue;
      const id = String(msg.id);
      if (!decryptedMessages.has(id) && !decryptingIds.has(id)) newIds.push(id);
    }
    if (newIds.length === 0) return;
    setDecryptingIds((prev) => {
      const next = new Set(prev);
      for (const id of newIds) next.add(id);
      return next;
    });
    const msgsToDecrypt = messages.filter(
      (m) => !m.isImage && newIds.includes(String(m.id)),
    );
    Promise.all(
      msgsToDecrypt.map(async (msg) => {
        const id = String(msg.id);
        const isMine = msg.sender === currentUser;
        if (!isEncryptedEnvelope(msg.content))
          return [id, null] as [string, null];
        const plaintext = await decryptMessage(msg.content, privateKey, isMine);
        return [id, plaintext] as [string, string | null];
      }),
    ).then((results) => {
      setDecryptedMessages((prev) => {
        const next = new Map(prev);
        for (const [id, text] of results) next.set(id, text);
        return next;
      });
      setDecryptingIds((prev) => {
        const next = new Set(prev);
        for (const [id] of results) next.delete(id);
        return next;
      });
    });
  }, [messages]);

  // Decrypt IMAGE messages
  // biome-ignore lint/correctness/useExhaustiveDependencies: decrypt when messages array changes
  useEffect(() => {
    if (!privateKeyRef.current || messages.length === 0) return;
    const privateKey = privateKeyRef.current;
    const newImageIds: string[] = [];
    for (const msg of messages) {
      if (!msg.isImage) continue;
      const id = String(msg.id);
      if (!decryptedImages.has(id) && !decryptingImageIds.has(id))
        newImageIds.push(id);
    }
    if (newImageIds.length === 0) return;
    setDecryptingImageIds((prev) => {
      const next = new Set(prev);
      for (const id of newImageIds) next.add(id);
      return next;
    });
    const imageMsgs = messages.filter(
      (m) => m.isImage && newImageIds.includes(String(m.id)),
    );
    Promise.all(
      imageMsgs.map(async (msg) => {
        const id = String(msg.id);
        const isMine = msg.sender === currentUser;
        try {
          const envelope = parseImageEnvelope(msg.content);
          if (!envelope) return [id, "error"] as [string, "error"];
          const encryptedData = b64ToBuf(envelope.data);
          const wrappedKey = isMine
            ? envelope.senderKey
            : envelope.recipientKey;
          const decrypted = await decryptBytes(
            encryptedData,
            envelope.iv,
            wrappedKey,
            privateKey,
          );
          if (!decrypted) return [id, "error"] as [string, "error"];
          const mimeType = envelope.mimeType || "image/jpeg";
          const objectUrl = URL.createObjectURL(
            new Blob([decrypted], { type: mimeType }),
          );
          imageObjectUrlsRef.current.set(id, objectUrl);
          return [id, objectUrl] as [string, string];
        } catch (err) {
          console.error("Image decryption failed", err);
          return [id, "error"] as [string, "error"];
        }
      }),
    ).then((results) => {
      setDecryptedImages((prev) => {
        const next = new Map(prev);
        for (const [id, url] of results) next.set(id, url);
        return next;
      });
      setDecryptingImageIds((prev) => {
        const next = new Set(prev);
        for (const [id] of results) next.delete(id);
        return next;
      });
    });
  }, [messages]);

  // Auto-scroll
  // biome-ignore lint/correctness/useExhaustiveDependencies: scroll on message count change
  useEffect(() => {
    scrollRef.current?.scrollIntoView?.({ block: "end" });
    if (scrollRef.current)
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages]);

  // Unsend handler
  const handleUnsend = useCallback(
    async (msgId: string) => {
      if (!actor) return;
      setUnsendMenuId(null);
      try {
        await (actor as any).unsendMessage(
          BigInt(msgId),
          currentUser,
          passwordHash,
        );
        setMessages((prev) => prev.filter((m) => String(m.id) !== msgId));
      } catch (err) {
        toast.error("Failed to unsend message.");
        console.error(err);
      }
    },
    [actor, currentUser, passwordHash],
  );

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!actor || !selectedUser || !messageText.trim()) return;
    setSending(true);
    const text = messageText.trim();
    setMessageText("");
    try {
      let content = text;
      if (cryptoReady && publicKeyRef.current && privateKeyRef.current) {
        try {
          let recipientPubB64: string | null = null;
          for (let attempt = 0; attempt < 3; attempt++) {
            recipientPubB64 = await actor.getPublicKey(selectedUser);
            if (recipientPubB64) break;
            if (attempt < 2) await new Promise((r) => setTimeout(r, 1000));
          }
          if (!recipientPubB64) {
            toast.error(
              "Cannot send: recipient needs to log in once to register their encryption key.",
            );
            setMessageText(text);
            setSending(false);
            return;
          }
          {
            const recipientPubKey = await importPublicKey(recipientPubB64);
            content = await encryptMessage(
              text,
              publicKeyRef.current,
              recipientPubKey,
            );
          }
        } catch (cryptoErr) {
          console.warn("Encryption failed", cryptoErr);
          toast.error("Encryption failed. Message not sent.");
          setMessageText(text);
          setSending(false);
          return;
        }
      }
      await (actor as any).sendMessage(
        currentUser,
        passwordHash,
        selectedUser,
        content,
        false,
      );
      await fetchMessages();
    } catch (err) {
      toast.error("Failed to send message");
      setMessageText(text);
      console.error(err);
    } finally {
      setSending(false);
    }
  };

  const handleImageSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = "";
    if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
      toast.error("Only JPEG, PNG, GIF, and WebP images are supported.");
      return;
    }
    if (file.size > MAX_IMAGE_SIZE) {
      toast.error("Image must be 7MB or smaller.");
      return;
    }
    if (
      !actor ||
      !selectedUser ||
      !cryptoReady ||
      !publicKeyRef.current ||
      !privateKeyRef.current
    ) {
      toast.error("Encryption not ready. Please wait.");
      return;
    }
    setSending(true);
    setEncryptingImage(true);
    try {
      const rawData = await file.arrayBuffer();
      let recipientPubB64: string | null = null;
      for (let attempt = 0; attempt < 3; attempt++) {
        recipientPubB64 = await actor.getPublicKey(selectedUser);
        if (recipientPubB64) break;
        if (attempt < 2) await new Promise((r) => setTimeout(r, 1000));
      }
      if (!recipientPubB64) {
        toast.error(
          "Recipient needs to log in once to register their encryption key.",
        );
        return;
      }
      const recipientPubKey = await importPublicKey(recipientPubB64);
      const { encryptedData, iv, senderKey, recipientKey } = await encryptBytes(
        rawData,
        publicKeyRef.current,
        recipientPubKey,
      );
      const dataB64 = bufToB64(encryptedData);
      const envelope: ImageEnvelope = {
        type: "image",
        data: dataB64,
        mimeType: file.type,
        iv,
        senderKey,
        recipientKey,
      };
      await (actor as any).sendMessage(
        currentUser,
        passwordHash,
        selectedUser,
        JSON.stringify(envelope),
        true,
      );
      await fetchMessages();
    } catch (err) {
      toast.error("Failed to send image. Please try again.");
      console.error(err);
    } finally {
      setSending(false);
      setEncryptingImage(false);
    }
  };

  const filteredUsers = users.filter((u) =>
    u.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse 80% 40% at 50% 0%, oklch(0.22 0.055 255 / 0.3) 0%, transparent 70%)",
        }}
      />

      <header className="bg-chat-nav border-b border-border sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              className="md:hidden h-8 w-8 text-chat-meta hover:text-foreground"
              onClick={() => {
                setSidebarOpen(true);
                setSelectedUser(null);
              }}
              title="Open contacts"
            >
              <Menu className="w-5 h-5" />
            </Button>
            <div
              className="w-7 h-7 rounded-md flex items-center justify-center flex-shrink-0"
              style={{ background: "oklch(0.55 0.17 255)" }}
            >
              <Lock className="w-4 h-4 text-white" />
            </div>
            <span className="font-bold text-foreground tracking-tight">
              CipherChat
            </span>
          </div>
          <nav className="hidden md:flex items-center gap-6 text-sm text-chat-meta">
            <span className="flex items-center gap-1.5 text-xs font-medium">
              <Lock
                className="w-3 h-3"
                style={{
                  color: cryptoReady
                    ? "oklch(0.65 0.17 150)"
                    : "oklch(0.60 0.17 60)",
                }}
              />
              <span
                style={{
                  color: cryptoReady
                    ? "oklch(0.65 0.17 150)"
                    : "oklch(0.60 0.17 60)",
                }}
              >
                {cryptoReady ? "E2EE Active" : "Setting up encryption…"}
              </span>
            </span>
          </nav>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-muted border border-border">
              <div
                className="w-6 h-6 rounded-full flex items-center justify-center text-white text-xs font-bold flex-shrink-0"
                style={{ background: avatarColor(currentUser) }}
              >
                {getInitials(currentUser)}
              </div>
              <span className="text-sm font-medium text-foreground hidden sm:block">
                {currentUser}
              </span>
            </div>
            <Button
              data-ocid="app.logout.button"
              variant="ghost"
              size="icon"
              onClick={onLogout}
              className="text-chat-meta hover:text-foreground h-8 w-8"
              title="Log out"
            >
              <LogOut className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </header>

      <main className="relative flex-1 max-w-7xl w-full mx-auto md:px-4 md:py-6 flex">
        <div
          className="flex-1 rounded-2xl border border-border shadow-card overflow-hidden flex"
          style={{
            background: "oklch(0.22 0.03 235)",
            minHeight: "calc(100vh - 7.5rem)",
          }}
        >
          {/* Sidebar */}
          <aside
            className={`${sidebarOpen ? "flex" : "hidden"} md:flex w-full md:w-72 flex-shrink-0 border-r border-border flex-col`}
            style={{ background: "oklch(0.24 0.025 230)" }}
          >
            <div className="p-4 border-b border-border">
              <h2 className="font-semibold text-foreground mb-3">
                Active Chats
              </h2>
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 w-4 h-4 text-muted-foreground" />
                <Input
                  data-ocid="sidebar.search_input"
                  placeholder="Search users…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8 h-9 bg-input border-border text-foreground placeholder:text-muted-foreground text-sm"
                />
              </div>
            </div>
            <ScrollArea className="flex-1">
              {loadingUsers ? (
                <div
                  className="flex items-center justify-center py-12"
                  data-ocid="sidebar.loading_state"
                >
                  <Loader2 className="w-5 h-5 animate-spin text-primary" />
                </div>
              ) : filteredUsers.length === 0 ? (
                <div
                  className="flex flex-col items-center justify-center py-12 px-4 gap-2"
                  data-ocid="sidebar.empty_state"
                >
                  <Users className="w-8 h-8 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground text-center">
                    {search
                      ? "No users match your search"
                      : "No other users yet"}
                  </p>
                </div>
              ) : (
                <ul className="py-2">
                  {filteredUsers.map((user, i) => (
                    <li key={user}>
                      <button
                        type="button"
                        data-ocid={`sidebar.item.${i + 1}`}
                        onClick={() => {
                          setSelectedUser(user);
                          setSidebarOpen(false);
                        }}
                        className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-all duration-150 hover:bg-accent/50 hover:scale-[1.015] active:scale-[0.99] ${
                          selectedUser === user ? "bg-accent/70" : ""
                        }`}
                      >
                        <div className="relative flex-shrink-0">
                          <div
                            className="w-10 h-10 rounded-full flex items-center justify-center text-white text-sm font-bold"
                            style={{ background: avatarColor(user) }}
                          >
                            {getInitials(user)}
                          </div>
                          <span
                            className="dot-online absolute bottom-0 right-0 border-2"
                            style={{ borderColor: "oklch(0.24 0.025 230)" }}
                          />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-foreground truncate">
                            {user}
                          </p>
                          <p className="text-xs text-chat-meta truncate">
                            {user}
                          </p>
                        </div>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </ScrollArea>
          </aside>

          {/* Conversation panel */}
          <section
            className={`${sidebarOpen ? "hidden md:flex" : "flex"} flex-1 flex-col`}
            style={{ background: "oklch(0.28 0.022 228)" }}
          >
            {selectedUser ? (
              <div
                key={selectedUser}
                className="animate-chat-open flex-1 flex flex-col overflow-hidden"
              >
                {/* Chat header */}
                <div
                  className="px-5 py-3.5 border-b border-border flex items-center gap-3"
                  style={{ background: "oklch(0.22 0.03 235)" }}
                >
                  <Button
                    variant="ghost"
                    size="icon"
                    className="md:hidden h-8 w-8 text-chat-meta hover:text-foreground flex-shrink-0"
                    onClick={() => {
                      setSidebarOpen(true);
                      setSelectedUser(null);
                    }}
                    title="Back to contacts"
                  >
                    <ArrowLeft className="w-5 h-5" />
                  </Button>
                  <div className="relative flex-shrink-0">
                    <div
                      className="w-9 h-9 rounded-full flex items-center justify-center text-white text-sm font-bold"
                      style={{ background: avatarColor(selectedUser) }}
                    >
                      {getInitials(selectedUser)}
                    </div>
                    <span
                      className="dot-online absolute bottom-0 right-0 border-2"
                      style={{ borderColor: "oklch(0.22 0.03 235)" }}
                    />
                  </div>
                  <div className="flex-1">
                    <p className="font-semibold text-foreground text-sm">
                      {selectedUser}
                    </p>
                    <p className="text-xs text-chat-meta">Online</p>
                  </div>
                  <div
                    className="flex items-center gap-1 px-2 py-1 rounded-full text-xs"
                    style={{
                      background: cryptoReady
                        ? "oklch(0.65 0.17 150 / 0.15)"
                        : "oklch(0.60 0.10 60 / 0.15)",
                      color: cryptoReady
                        ? "oklch(0.75 0.17 150)"
                        : "oklch(0.70 0.10 60)",
                      border: `1px solid ${
                        cryptoReady
                          ? "oklch(0.65 0.17 150 / 0.3)"
                          : "oklch(0.60 0.10 60 / 0.3)"
                      }`,
                    }}
                  >
                    {cryptoReady ? (
                      <Lock className="w-3 h-3" />
                    ) : (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    )}
                    <span>{cryptoReady ? "Encrypted" : "Setting up…"}</span>
                  </div>
                </div>

                {/* Messages */}
                <div
                  ref={scrollRef}
                  className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-2"
                  data-ocid="chat.panel"
                >
                  {loadingMessages && messages.length === 0 ? (
                    <div
                      className="flex items-center justify-center py-12"
                      data-ocid="chat.loading_state"
                    >
                      <Loader2 className="w-5 h-5 animate-spin text-primary" />
                    </div>
                  ) : messages.length === 0 ? (
                    <div
                      className="flex flex-col items-center justify-center flex-1 gap-3"
                      data-ocid="chat.empty_state"
                    >
                      <MessageSquare className="w-10 h-10 text-muted-foreground" />
                      <p className="text-sm text-muted-foreground">
                        No messages yet. Say hello!
                      </p>
                    </div>
                  ) : (
                    messages.map((msg, i) => {
                      const isMine = msg.sender === currentUser;
                      const msgId = String(msg.id);
                      const isMenuOpen = unsendMenuId === msgId;

                      return (
                        <div
                          key={msgId}
                          data-ocid={`chat.item.${i + 1}`}
                          className={`flex ${
                            isMine
                              ? "justify-end animate-msg-in-right"
                              : "justify-start animate-msg-in-left"
                          }`}
                        >
                          {!isMine && (
                            <div
                              className="w-7 h-7 rounded-full flex items-center justify-center text-white text-xs font-bold flex-shrink-0 mr-2 mt-auto"
                              style={{ background: avatarColor(msg.sender) }}
                            >
                              {getInitials(msg.sender)}
                            </div>
                          )}
                          <div
                            className={`max-w-xs lg:max-w-sm xl:max-w-md flex flex-col relative ${
                              isMine ? "items-end" : "items-start"
                            }`}
                          >
                            {msg.isImage ? (
                              <ImageBubble
                                msgId={msgId}
                                isMine={isMine}
                                decryptedImages={decryptedImages}
                                decryptingImageIds={decryptingImageIds}
                                timestamp={msg.timestamp}
                                onLongPress={
                                  isMine
                                    ? () => setUnsendMenuId(msgId)
                                    : undefined
                                }
                              />
                            ) : (
                              <TextBubble
                                msgId={msgId}
                                isMine={isMine}
                                content={msg.content}
                                decryptedMessages={decryptedMessages}
                                decryptingIds={decryptingIds}
                                timestamp={msg.timestamp}
                                onLongPress={
                                  isMine
                                    ? () => setUnsendMenuId(msgId)
                                    : undefined
                                }
                              />
                            )}

                            {/* Unsend context menu */}
                            {isMine && isMenuOpen && (
                              <div
                                className="absolute z-30"
                                style={{
                                  bottom: "calc(100% + 4px)",
                                  right: 0,
                                }}
                                onMouseDown={(e) => e.stopPropagation()}
                                onTouchStart={(e) => e.stopPropagation()}
                                data-ocid="chat.popover"
                              >
                                <button
                                  type="button"
                                  data-ocid="chat.delete_button"
                                  onClick={() => handleUnsend(msgId)}
                                  className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-colors animate-pop-in"
                                  style={{
                                    background: "oklch(0.20 0.03 235)",
                                    border: "1px solid oklch(0.35 0.03 235)",
                                    color: "oklch(0.72 0.18 30)",
                                    boxShadow: "0 4px 16px oklch(0 0 0 / 0.4)",
                                  }}
                                >
                                  <Trash2 className="w-3 h-3" />
                                  Unsend
                                </button>
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

                {/* Composer */}
                <form
                  onSubmit={handleSend}
                  className="px-4 py-3 border-t border-border flex items-center gap-2"
                  style={{ background: "oklch(0.22 0.03 235)" }}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/jpeg,image/png,image/gif,image/webp"
                    className="hidden"
                    onChange={handleImageSelect}
                    data-ocid="chat.upload_button"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    disabled={sending || !cryptoReady}
                    onClick={() => fileInputRef.current?.click()}
                    className="h-9 w-9 flex-shrink-0 text-chat-meta hover:text-foreground"
                    title="Send image (max 7MB)"
                    data-ocid="chat.secondary_button"
                  >
                    {encryptingImage ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <ImageIcon className="w-4 h-4" />
                    )}
                  </Button>
                  <Input
                    data-ocid="chat.message.input"
                    placeholder={
                      encryptingImage
                        ? "Encrypting image…"
                        : !cryptoReady
                          ? "Setting up encryption…"
                          : `Message ${selectedUser}…`
                    }
                    value={messageText}
                    onChange={(e) => setMessageText(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        handleSend(e);
                      }
                    }}
                    disabled={sending || !cryptoReady}
                    className="flex-1 bg-input border-border text-foreground placeholder:text-muted-foreground focus-visible:ring-primary"
                  />
                  <Button
                    data-ocid="chat.send_button"
                    type="submit"
                    size="icon"
                    disabled={sending || !messageText.trim() || !cryptoReady}
                    className="h-9 w-9 flex-shrink-0"
                    title={!cryptoReady ? "Setting up encryption…" : "Send"}
                    style={{
                      background: "oklch(0.55 0.17 255)",
                      color: "white",
                      transition: "transform 100ms ease, opacity 100ms ease",
                    }}
                    onMouseDown={(e) => {
                      (e.currentTarget as HTMLButtonElement).style.transform =
                        "scale(0.88)";
                    }}
                    onMouseUp={(e) => {
                      (e.currentTarget as HTMLButtonElement).style.transform =
                        "";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLButtonElement).style.transform =
                        "";
                    }}
                  >
                    {sending || !cryptoReady ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Send className="w-4 h-4" />
                    )}
                  </Button>
                </form>
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center gap-4">
                <div
                  className="w-16 h-16 rounded-2xl flex items-center justify-center"
                  style={{ background: "oklch(0.55 0.17 255 / 0.15)" }}
                >
                  <MessageSquare
                    className="w-8 h-8"
                    style={{ color: "oklch(0.55 0.17 255)" }}
                  />
                </div>
                <p className="text-muted-foreground text-sm">
                  Select a user to start chatting
                </p>
              </div>
            )}
          </section>
        </div>
      </main>

      <footer className="relative text-center text-xs text-chat-meta py-4">
        © {new Date().getFullYear()}. Built with{" "}
        <span style={{ color: "oklch(0.72 0.17 30)" }}>♥</span> using{" "}
        <a
          href={`https://caffeine.ai?utm_source=caffeine-footer&utm_medium=referral&utm_content=${encodeURIComponent(window.location.hostname)}`}
          className="hover:text-foreground transition-colors"
          target="_blank"
          rel="noopener noreferrer"
        >
          caffeine.ai
        </a>
      </footer>
    </div>
  );
}

// ── TextBubble ────────────────────────────────────────────────────────────────
function TextBubble({
  msgId,
  isMine,
  content,
  decryptedMessages,
  decryptingIds,
  timestamp,
  onLongPress,
}: {
  msgId: string;
  isMine: boolean;
  content: string;
  decryptedMessages: Map<string, string | null>;
  decryptingIds: Set<string>;
  timestamp: bigint;
  onLongPress?: () => void;
}) {
  const isDecrypting = decryptingIds.has(msgId);
  const decryptedText = decryptedMessages.get(msgId);
  const isEncrypted = isEncryptedEnvelope(content);

  let displayText: string;
  let showLock: "encrypted" | "plain" | "decrypting";
  if (isDecrypting) {
    displayText = "…";
    showLock = "decrypting";
  } else if (
    isEncrypted &&
    decryptedText !== null &&
    decryptedText !== undefined
  ) {
    displayText = decryptedText;
    showLock = "encrypted";
  } else if (isEncrypted && decryptedText === null) {
    displayText = "[encrypted — could not decrypt]";
    showLock = "plain";
  } else {
    displayText = content;
    showLock = "plain";
  }

  const longPressHandlers = useLongPress(onLongPress ?? (() => {}), 600);

  return (
    <>
      <div
        {...(onLongPress ? longPressHandlers : {})}
        className={`px-3.5 py-2 rounded-2xl text-sm leading-relaxed select-none ${
          isMine
            ? "bg-bubble-out text-white rounded-br-sm"
            : "bg-bubble-in text-foreground rounded-bl-sm"
        } ${onLongPress ? "cursor-pointer" : ""}`}
        style={
          onLongPress ? { WebkitUserSelect: "none", userSelect: "none" } : {}
        }
      >
        {isDecrypting ? (
          <Loader2 className="w-3 h-3 animate-spin inline" />
        ) : (
          <span>{renderTextWithLinks(displayText)}</span>
        )}
      </div>
      <div className="flex items-center gap-1 mt-1 px-1">
        {showLock === "encrypted" && (
          <Lock
            className="w-2.5 h-2.5"
            style={{ color: "oklch(0.65 0.17 150)" }}
          />
        )}
        {showLock === "plain" && (
          <LockOpen className="w-2.5 h-2.5 text-muted-foreground" />
        )}
        <span className="text-xs text-chat-meta">{formatTime(timestamp)}</span>
      </div>
    </>
  );
}

// ── ImageBubble ───────────────────────────────────────────────────────────────
function ImageBubble({
  msgId,
  isMine,
  decryptedImages,
  decryptingImageIds,
  timestamp,
  onLongPress,
}: {
  msgId: string;
  isMine: boolean;
  decryptedImages: Map<string, string | "error">;
  decryptingImageIds: Set<string>;
  timestamp: bigint;
  onLongPress?: () => void;
}) {
  const isDecrypting = decryptingImageIds.has(msgId);
  const imageResult = decryptedImages.get(msgId);
  const longPressHandlers = useLongPress(onLongPress ?? (() => {}), 600);

  return (
    <>
      <div
        {...(onLongPress ? longPressHandlers : {})}
        className={`rounded-2xl overflow-hidden ${
          isMine ? "rounded-br-sm" : "rounded-bl-sm"
        } ${onLongPress ? "cursor-pointer" : ""}`}
        style={{
          background: isMine ? "oklch(0.45 0.17 255)" : "oklch(0.30 0.022 228)",
          maxWidth: "16rem",
          WebkitUserSelect: "none",
          userSelect: "none",
        }}
      >
        {isDecrypting || !imageResult ? (
          <div
            className="flex items-center justify-center gap-2 px-4 py-6 text-xs"
            style={{
              color: isMine ? "rgba(255,255,255,0.7)" : "oklch(0.60 0.02 228)",
            }}
            data-ocid="chat.loading_state"
          >
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Decrypting…</span>
          </div>
        ) : imageResult === "error" ? (
          <div
            className="flex items-center justify-center gap-1.5 px-4 py-4 text-xs"
            style={{ color: "oklch(0.65 0.18 30)" }}
            data-ocid="chat.error_state"
          >
            <LockOpen className="w-3.5 h-3.5" />
            <span>Could not decrypt image</span>
          </div>
        ) : (
          <img
            src={imageResult}
            alt="Secure attachment"
            className="w-full h-auto block animate-fade-in"
            style={{
              maxWidth: "16rem",
              maxHeight: "20rem",
              objectFit: "contain",
            }}
            draggable={false}
          />
        )}
      </div>
      <div className="flex items-center gap-1 mt-1 px-1">
        <Lock
          className="w-2.5 h-2.5"
          style={{
            color:
              imageResult && imageResult !== "error"
                ? "oklch(0.65 0.17 150)"
                : "oklch(0.50 0.02 228)",
          }}
        />
        <span className="text-xs text-chat-meta">{formatTime(timestamp)}</span>
      </div>
    </>
  );
}

// ── App Root ──────────────────────────────────────────────────────────────────
export default function App() {
  const [currentUser, setCurrentUser] = useState<string | null>(() => {
    return localStorage.getItem("cc_user");
  });

  const [passwordHash, setPasswordHash] = useState<string>(
    () => localStorage.getItem("cc_phash") ?? "",
  );

  const handleLogin = (username: string, hash: string) => {
    localStorage.setItem("cc_phash", hash);
    setPasswordHash(hash);
    setCurrentUser(username);
  };
  const handleLogout = () => {
    localStorage.removeItem("cc_user");
    localStorage.removeItem("cc_phash");
    setCurrentUser(null);
    setPasswordHash("");
  };

  return (
    <>
      <Toaster richColors position="top-right" />
      {currentUser ? (
        <div key="chat" className="animate-fade-in">
          <ChatApp
            currentUser={currentUser}
            onLogout={handleLogout}
            passwordHash={passwordHash}
          />
        </div>
      ) : (
        <div key="auth" className="animate-fade-in">
          <AuthScreen onLogin={handleLogin} />
        </div>
      )}
    </>
  );
}
