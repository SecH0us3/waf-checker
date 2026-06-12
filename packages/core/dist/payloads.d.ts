export type PayloadCategory = {
    type: 'ParamCheck' | 'FileCheck' | 'Header';
    payloads: string[];
    falsePayloads: string[];
};
export declare const PAYLOADS: Record<string, PayloadCategory>;
export declare const ENHANCED_PAYLOADS: {
    [x: string]: PayloadCategory;
};
