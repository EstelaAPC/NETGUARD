import React from "react";

function renderInline(text, keyPrefix) {
  const segments = [];
  const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match;
  let segmentIndex = 0;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      segments.push(
        <React.Fragment key={`${keyPrefix}-text-${segmentIndex++}`}>
          {text.slice(lastIndex, match.index)}
        </React.Fragment>
      );
    }

    const token = match[0];
    if (token.startsWith("**") && token.endsWith("**")) {
      segments.push(
        <strong key={`${keyPrefix}-strong-${segmentIndex++}`} className="font-semibold text-white">
          {token.slice(2, -2)}
        </strong>
      );
    } else if (token.startsWith("`") && token.endsWith("`")) {
      segments.push(
        <code
          key={`${keyPrefix}-code-${segmentIndex++}`}
          className="rounded bg-slate-950 px-1.5 py-0.5 text-[0.92em] text-sky-100"
        >
          {token.slice(1, -1)}
        </code>
      );
    }

    lastIndex = regex.lastIndex;
  }

  if (lastIndex < text.length) {
    segments.push(
      <React.Fragment key={`${keyPrefix}-tail-${segmentIndex++}`}>
        {text.slice(lastIndex)}
      </React.Fragment>
    );
  }

  return segments;
}

export default function SafeMarkdown({ content = "" }) {
  const lines = String(content || "").replace(/\r/g, "").split("\n");
  const blocks = [];
  let paragraph = [];
  let unordered = [];
  let ordered = [];
  let blockIndex = 0;

  function flushParagraph() {
    if (!paragraph.length) return;
    const text = paragraph.join(" ").trim();
    if (text) {
      blocks.push(
        <p key={`p-${blockIndex++}`} className="text-sm leading-7 text-slate-200">
          {renderInline(text, `p-${blockIndex}`)}
        </p>
      );
    }
    paragraph = [];
  }

  function flushUnordered() {
    if (!unordered.length) return;
    blocks.push(
      <ul key={`ul-${blockIndex++}`} className="list-disc space-y-2 pl-5 text-sm leading-7 text-slate-200">
        {unordered.map((item, index) => (
          <li key={`ul-item-${index}`}>{renderInline(item, `ul-${blockIndex}-${index}`)}</li>
        ))}
      </ul>
    );
    unordered = [];
  }

  function flushOrdered() {
    if (!ordered.length) return;
    blocks.push(
      <ol key={`ol-${blockIndex++}`} className="list-decimal space-y-2 pl-5 text-sm leading-7 text-slate-200">
        {ordered.map((item, index) => (
          <li key={`ol-item-${index}`}>{renderInline(item, `ol-${blockIndex}-${index}`)}</li>
        ))}
      </ol>
    );
    ordered = [];
  }

  function flushAll() {
    flushParagraph();
    flushUnordered();
    flushOrdered();
  }

  lines.forEach((rawLine) => {
    const line = rawLine.trim();

    if (!line) {
      flushAll();
      return;
    }

    const headingMatch = /^(#{1,3})\s+(.+)$/.exec(line);
    if (headingMatch) {
      flushAll();
      const level = headingMatch[1].length;
      const headingText = headingMatch[2];
      const className =
        level === 1
          ? "text-lg font-semibold text-white"
          : level === 2
          ? "text-sm font-semibold uppercase tracking-[0.14em] text-slate-400"
          : "text-sm font-semibold text-slate-200";
      blocks.push(
        <div key={`h-${blockIndex++}`} className={className}>
          {renderInline(headingText, `h-${blockIndex}`)}
        </div>
      );
      return;
    }

    const unorderedMatch = /^[-*]\s+(.+)$/.exec(line);
    if (unorderedMatch) {
      flushParagraph();
      flushOrdered();
      unordered.push(unorderedMatch[1]);
      return;
    }

    const orderedMatch = /^\d+\.\s+(.+)$/.exec(line);
    if (orderedMatch) {
      flushParagraph();
      flushUnordered();
      ordered.push(orderedMatch[1]);
      return;
    }

    flushUnordered();
    flushOrdered();
    paragraph.push(line);
  });

  flushAll();

  if (!blocks.length) {
    return <div className="text-sm text-slate-400">Sem conteudo gerado.</div>;
  }

  return <div className="space-y-4">{blocks}</div>;
}
