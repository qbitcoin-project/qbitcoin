import type { ComponentType, SVGProps } from 'react';

import { Logo } from './Logo';

export interface BrandConfig {
    assetLabel: { main: string; testnet: string };
    assetName: string;
    addressMainnetRe: RegExp;
    addressTestnetRe: RegExp;
    logoSize: { width: number; height: number };
    accent?: { light: string; dark: string };
    CoinIcon?: ComponentType<SVGProps<SVGSVGElement>>;
    powChain?: {
        label: string;
        explorerTxUrl: { main: string; testnet: string };
    };
}

export const brand: BrandConfig = {
    assetLabel: { main: 'QBTC', testnet: 'tQBTC' },
    assetName: 'QBitcoin',
    addressMainnetRe: /^(?:bq[1-9A-HJ-NP-Za-km-z]{33}|3u[H-K][1-9A-HJ-NP-Za-km-z]{49})$/,
    addressTestnetRe: /^(?:btq[1-9A-HJ-NP-Za-km-z]{33}|3ua[234][1-9A-HJ-NP-Za-km-z]{49})$/,
    logoSize: { width: 48, height: 48 },
    accent: { light: '#c2560d', dark: '#fd7007' },
};

export { Logo };
