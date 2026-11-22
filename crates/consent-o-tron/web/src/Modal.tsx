import { useEffect, useRef, type ReactNode } from "react";

/** A modal dialog in the page's style. Escape and the close button call `onClose`. */
export function Modal({
  title,
  onClose,
  wide = false,
  children,
}: {
  title: ReactNode;
  onClose?: () => void;
  wide?: boolean;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current!;
    if (!dialog.open) dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className={`modal${wide ? " modal-wide" : ""}`}
      onCancel={(e) => {
        e.preventDefault();
        onClose?.();
      }}
    >
      <div className="modal-head">
        <h2>{title}</h2>
        {onClose && (
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            ×
          </button>
        )}
      </div>
      <div className="modal-body">{children}</div>
    </dialog>
  );
}
