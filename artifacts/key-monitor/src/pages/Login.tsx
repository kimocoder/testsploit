import { useState } from "react";
import { ShieldAlert, Loader2 } from "lucide-react";

interface Props { onSuccess: () => void }

export default function Login({ onSuccess }: Props) {
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (submitting || !password) return;
    setSubmitting(true);
    setError(null);
    try {
      const r = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ password }),
      });
      if (r.ok) {
        onSuccess();
        return;
      }
      if (r.status === 429) setError("Слишком много попыток. Подожди 15 минут.");
      else if (r.status === 401) setError("Неверный пароль.");
      else setError(`Ошибка ${r.status}`);
    } catch (err) {
      setError(`Сеть: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-background p-6">
      <div className="w-full max-w-sm">
        <div className="flex items-center justify-center mb-8">
          <ShieldAlert className="w-8 h-8 text-primary mr-3" />
          <span className="text-xl font-bold tracking-wider text-primary">KMON_NOC</span>
        </div>
        <form
          onSubmit={submit}
          className="bg-card border border-border rounded-lg p-6 space-y-4"
        >
          <div>
            <label className="block text-xs uppercase text-muted-foreground mb-2">
              Пароль доступа
            </label>
            <input
              type="password"
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={submitting}
              className="w-full bg-background border border-border rounded px-3 py-2 text-sm font-mono outline-none focus:border-primary disabled:opacity-50"
              placeholder="••••••••••••••••"
            />
          </div>
          {error && (
            <div className="text-xs text-red-400 border border-red-500/30 bg-red-500/10 rounded px-3 py-2">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={submitting || !password}
            className="w-full bg-primary text-primary-foreground rounded px-3 py-2 text-sm font-bold uppercase tracking-wider hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
          >
            {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : "Войти"}
          </button>
        </form>
        <div className="text-center text-xs text-muted-foreground mt-4">
          Авторизация требуется для всех endpoints.
        </div>
      </div>
    </div>
  );
}
