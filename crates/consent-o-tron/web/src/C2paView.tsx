// The Content Credentials viewer, in its own chunk: its provenance graph
// (@xyflow/react) is most of its weight, and only the verify pages need it.
import { C2paManifest } from "c2pa-react-component";
import { CAWGManifest } from "c2pa-react-cawg-component";
import "c2pa-react-component/style.css";
import "c2pa-react-cawg-component/style.css";
import { toOutcome, type RsManifestStore } from "./c2pa";

export default function C2paView({ store }: { store: RsManifestStore }) {
  const outcome = toOutcome(store);
  if (!outcome.manifestStore) return null;
  return <C2paManifest manifest={outcome} level={2} defaultViewMore plugin={[CAWGManifest]} className="c2pa-card--fluid" />;
}
