import { ShieldAlert } from "lucide-react";
import { useApp } from "../state";

/** Shown before any AI call on real (non-synthetic) data. Nothing is sent until the box is ticked. */
export function RealDataConsent() {
  const { realData, aiConsent, setAiConsent } = useApp();
  if (!realData) return null;
  return (
    <div className="consent">
      <ShieldAlert size={18} aria-hidden />
      <div>
        <strong>This is real data, not synthetic</strong>
        <p className="small">Using Meta AI sends this finding's evidence to the Meta Model API: identity names, policy
          statements and resource ARNs (which can include your AWS account ID). Nothing else from the dataset is sent.</p>
        <label className="consent-check">
          <input type="checkbox" checked={aiConsent} onChange={(e) => setAiConsent(e.target.checked)} />
          <span>I am authorised to share this evidence with the Meta Model API</span>
        </label>
      </div>
    </div>
  );
}
