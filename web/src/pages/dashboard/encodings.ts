// The one place that says what every visual channel of the Threat Galaxy means.
// To add or change a mapping, edit ONLY this file: each channel names its source column and provenance,
// and the legend, tooltips and coach marks are generated from it.
import type { GalaxyData } from './data';

export type Layout = 'spiral' | 'split' | 'rows' | 'embedding';
export type Provenance = 'model' | 'snapshot' | 'observed' | 'embedding';
export type Channel = { field: string; source: string; provenance: Provenance; meaning: string };

export const ENCODINGS = {
  /** How stars are placed. 'embedding' needs x,y in /api/galaxy (optional Member 2 columns) and is hidden otherwise. */
  layouts: {
    spiral: {
      label: 'Galaxy',
      provenanceLabel: undefined as string | undefined,
      legend: ['Distance from the core = rank ({method})', 'Arm = family', 'Rotation and spread within an arm carry no meaning'],
    },
    split: {
      label: 'Split',
      provenanceLabel: undefined as string | undefined,
      legend: ['One cluster = one family', 'Distance from the cluster centre = rank within the family ({method})', 'Rotation and spread within a cluster carry no meaning'],
    },
    rows: {
      label: 'Chart',
      provenanceLabel: undefined as string | undefined,
      legend: ['Left to right = rank ({method}), log scale', 'Row = family', 'Vertical position within a row carries no meaning'],
    },
    embedding: {
      label: 'Semantic map',
      provenanceLabel: 'IBM Granite embedding (Member 2)' as string | undefined,
      legend: ['Position = 2-D projection of IBM Granite description embeddings', 'Nearby stars have similar descriptions', 'Rank is not encoded by position here; the Top 500 still glow'],
    },
  } as Record<Layout, { label: string; legend: string[]; provenanceLabel: string | undefined }>,

  /** Meaningful channel 1: distance from core (spiral) / x (rows) = rank percentile. */
  distance: { field: 'rank', source: 'predictions.csv · rank', provenance: 'model', meaning: 'Rank (current ranking method)', exponent: 0.6, rMin: 0.06 } as Channel & { exponent: number; rMin: number },
  /** Meaningful channel 2: arm (spiral) / row (chart) = family. */
  arm: { field: 'family', source: 'families.csv / granite_features.csv · family_id', provenance: 'embedding', meaning: 'Family', twist: 2.8 } as Channel & { twist: number },

  /** Star radius in px at 1x. */
  size: {
    field: 'epss', source: 'predictions.csv · epss', provenance: 'snapshot', meaning: 'EPSS',
    px: (d: GalaxyData, i: number): number => 0.6 + 2.6 * Math.min(1, Math.sqrt(Math.max(0, d.epssA[i])) / 0.8),
  } as Channel & { px: (d: GalaxyData, i: number) => number },
  /** Palette slot (family index; -1 = unknown). Colours come from --galaxy-* tokens. */
  colour: {
    field: 'family', source: 'families.csv / granite_features.csv · family_id', provenance: 'embedding', meaning: 'Family',
    slot: (d: GalaxyData, i: number): number => d.famA[i],
  } as Channel & { slot: (d: GalaxyData, i: number) => number },
  /** Soft halo + full brightness. */
  glow: {
    field: 'top500', source: 'top500.csv (or rank ≤ 500)', provenance: 'model', meaning: 'Top 500',
    on: (d: GalaxyData, i: number): boolean => !!d.topA[i],
  } as Channel & { on: (d: GalaxyData, i: number) => boolean },
  /** Subtle twinkle. */
  twinkle: {
    field: 'sig', source: 'predictions.csv · exploitdb | metasploit | nuclei | poc_github', provenance: 'snapshot', meaning: 'Public exploit code',
    on: (d: GalaxyData, i: number): boolean => d.sigA[i] !== 0,
  } as Channel & { on: (d: GalaxyData, i: number) => boolean },

  /** Real rank cut-offs, shared with the patch-budget chart. */
  rings: [100, 250, 500] as number[],
};

/** Symbol legend entries (layout-independent), generated from the channels above. */
export const LEGEND_SYMBOLS = [
  { kind: 'size', text: `Size = ${ENCODINGS.size.meaning}` },
  { kind: 'colour', text: `Colour = ${ENCODINGS.colour.meaning.toLowerCase()}` },
  { kind: 'glow', text: `Glow = ${ENCODINGS.glow.meaning}` },
  { kind: 'twinkle', text: `Twinkle = ${ENCODINGS.twinkle.meaning.toLowerCase()}` },
] as const;
