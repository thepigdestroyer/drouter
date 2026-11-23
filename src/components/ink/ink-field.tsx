"use client";

import { useEffect, useRef, useState } from "react";

const key = "deroute.ink-motion";
const pref = "(prefers-reduced-motion: reduce)";

export function InkMotionButton() {
  const [moving, setMoving] = useState<boolean | null>(null);
  useEffect(() => {
    const mq = matchMedia(pref);
    function sync() {
      let mode = document.documentElement.dataset.inkMotion;
      try { mode = localStorage.getItem(key) ?? mode; } catch { /* Storage is optional. */ }
      if (mode === "playing" || mode === "paused") document.documentElement.dataset.inkMotion = mode;
      setMoving(mode === "playing" || (mode !== "paused" && !mq.matches));
    }
    sync(); mq.addEventListener("change", sync); window.addEventListener("storage", sync);
    return () => { mq.removeEventListener("change", sync); window.removeEventListener("storage", sync); };
  }, []);
  return <button type="button" aria-label={moving ? "Pause ink animation" : "Play ink animation"} title={moving ? "Pause ink animation" : "Play ink animation"}
    disabled={moving === null} className="ep-btn-ghost rounded border border-rule px-2.5 py-1 text-xs"
    onClick={() => { const mode = moving ? "paused" : "playing"; document.documentElement.dataset.inkMotion = mode; try { localStorage.setItem(key, mode); } catch { /* Session only. */ } setMoving(!moving); }}>
    <span aria-hidden="true">{moving ? "Ⅱ" : "▷"} Ink</span></button>;
}

function Blot({ side }: { side: string }) {
  return <svg className={`ep-ink-drift ep-ink-${side}`} viewBox="0 0 220 240" fill="currentColor" focusable="false">
    <path opacity=".12" d="M34 48C62 15 116 25 132 57S146 91 176 91 211 121 192 141 163 143 154 182 97 237 67 208 47 174 26 152 6 82 34 48Z" />
    <path opacity=".69" d="M41 64C57 36 95 26 117 46S119 90 144 101 189 93 187 117 149 141 145 162 131 202 107 205 70 191 65 169 50 150 36 138 19 102 41 64Z" />
    <path opacity=".72" d="M48 74C61 47 97 38 107 55S113 95 127 103 132 132 118 145 120 177 100 182 77 158 59 148 27 114 48 74Z" />
    <path opacity=".48" d="M158 66c7-6 18-1 15 7s-15 11-18 3c-1-4 0-7 3-10Z" /><circle cx="186" cy="81" r="3.4" opacity=".65"/><circle cx="150" cy="205" r="4.7" opacity=".38"/>
  </svg>;
}

export function InkField() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const mq = matchMedia(pref);
    const pool = Array.from(ref.current!.querySelectorAll<HTMLElement>(".ep-ink-speck"));
    let i=0, last=-Infinity, lastX=-100, lastY=-100;
    function emit(e: PointerEvent) {
      if (document.hidden || !e.isPrimary || (e.type === "pointermove" && e.pointerType === "touch")) return;
      const mode = document.documentElement.dataset.inkMotion;
      if (mode === "paused" || (mq.matches && mode !== "playing")) return;
      if ((e.target as Element | null)?.closest?.("button,a,summary,input,textarea,select,[contenteditable=true],[role=button]")) return;
      const tap=e.type === "pointerdown";
      if (tap && e.button!==0) return;
      if (!tap && (e.timeStamp-last<35 || Math.hypot(e.clientX-lastX,e.clientY-lastY)<9)) return;
      last=e.timeStamp; lastX=e.clientX; lastY=e.clientY;
      const el=pool[i++%pool.length]; el.getAnimations().forEach(a=>a.cancel());
      const x=e.clientX-6,y=e.clientY-5, dx=Math.sin(i*2.4)*9;
      el.animate([{transform:`translate(${x}px,${y}px) scale(${tap?1.5:.78})`,opacity:.57}, {transform:`translate(${x+dx}px,${y+12}px) scale(${tap?3:.22})`,opacity:0}],{duration:tap?740:480,easing:"ease-out"});
    }
    window.addEventListener("pointermove",emit,{passive:true}); window.addEventListener("pointerdown",emit,{passive:true});
    return ()=>{window.removeEventListener("pointermove",emit); window.removeEventListener("pointerdown",emit); pool.forEach(el=>el.getAnimations().forEach(a=>a.cancel()));};
  },[]);
  return <div ref={ref} aria-hidden="true" data-ink-field="true" className="ep-ink-field">
    <Blot side="west"/><Blot side="east"/><Blot side="south"/>
    {Array.from({length:12},(_,i)=><span className="ep-ink-speck" key={i}/>)}
  </div>;
}

export default InkField;
