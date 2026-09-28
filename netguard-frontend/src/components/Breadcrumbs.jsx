import React from "react";
import { Link, useLocation } from "react-router-dom";
import { getBreadcrumbs } from "../navigation";

export default function Breadcrumbs({ items }) {
  const location = useLocation();
  const resolvedItems = items || getBreadcrumbs(location.pathname);

  if (!resolvedItems.length) {
    return null;
  }

  return (
    <nav className="text-xs font-medium uppercase tracking-[0.14em] text-slate-500" aria-label="Breadcrumb">
      <ol className="flex flex-wrap items-center gap-2">
        {resolvedItems.map((item, index) => {
          const isLast = index === resolvedItems.length - 1;

          return (
            <li key={`${item.label}-${index}`} className="flex items-center gap-2">
              {index > 0 ? <span className="text-slate-700">/</span> : null}
              {item.to && !isLast ? (
                <Link to={item.to} className="hover:text-slate-300">
                  {item.label}
                </Link>
              ) : (
                <span className={isLast ? "text-slate-300" : "text-slate-500"}>{item.label}</span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
