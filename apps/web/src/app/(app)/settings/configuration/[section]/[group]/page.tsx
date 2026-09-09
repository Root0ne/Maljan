"use client";

import { useParams } from "next/navigation";
import GroupPage from "../../GroupPage";

/** The rail's leaf route: the section and group segments, rendered by
 *  `GroupPage`. */
export default function ConfigurationGroupPage() {
  const params = useParams<{ section: string; group: string }>();
  const section = Array.isArray(params.section) ? params.section[0] : params.section;
  const group = Array.isArray(params.group) ? params.group[0] : params.group;

  if (!section || !group) {
    return <p role="alert">No such settings group.</p>;
  }
  return <GroupPage section={section} group={group} />;
}
