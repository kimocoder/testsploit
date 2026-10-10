import type { QueryKey, UseMutationOptions, UseMutationResult, UseQueryOptions, UseQueryResult } from "@tanstack/react-query";
import type { ActionResponse, AutoChainStatus, AutoChainTriggerResponse, GetMonitorResultsParams, HealthStatus, KeyResult, MonitorConfig, MonitorStats, MonitorStatus, ResultsPage, SourceStatus, ValidationResult } from "./api.schemas";
import { customFetch } from "../custom-fetch";
import type { ErrorType, BodyType } from "../custom-fetch";
type AwaitedInput<T> = PromiseLike<T> | T;
type Awaited<O> = O extends AwaitedInput<infer T> ? T : never;
type SecondParameter<T extends (...args: never) => unknown> = Parameters<T>[1];
/**
 * @summary Health check
 */
export declare const getHealthCheckUrl: () => string;
export declare const healthCheck: (options?: RequestInit) => Promise<HealthStatus>;
export declare const getHealthCheckQueryKey: () => readonly ["/api/healthz"];
export declare const getHealthCheckQueryOptions: <TData = Awaited<ReturnType<typeof healthCheck>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof healthCheck>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}) => UseQueryOptions<Awaited<ReturnType<typeof healthCheck>>, TError, TData> & {
    queryKey: QueryKey;
};
export type HealthCheckQueryResult = NonNullable<Awaited<ReturnType<typeof healthCheck>>>;
export type HealthCheckQueryError = ErrorType<unknown>;
/**
 * @summary Health check
 */
export declare function useHealthCheck<TData = Awaited<ReturnType<typeof healthCheck>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof healthCheck>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}): UseQueryResult<TData, TError> & {
    queryKey: QueryKey;
};
/**
 * @summary Get monitor current status
 */
export declare const getGetMonitorStatusUrl: () => string;
export declare const getMonitorStatus: (options?: RequestInit) => Promise<MonitorStatus>;
export declare const getGetMonitorStatusQueryKey: () => readonly ["/api/monitor/status"];
export declare const getGetMonitorStatusQueryOptions: <TData = Awaited<ReturnType<typeof getMonitorStatus>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getMonitorStatus>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}) => UseQueryOptions<Awaited<ReturnType<typeof getMonitorStatus>>, TError, TData> & {
    queryKey: QueryKey;
};
export type GetMonitorStatusQueryResult = NonNullable<Awaited<ReturnType<typeof getMonitorStatus>>>;
export type GetMonitorStatusQueryError = ErrorType<unknown>;
/**
 * @summary Get monitor current status
 */
export declare function useGetMonitorStatus<TData = Awaited<ReturnType<typeof getMonitorStatus>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getMonitorStatus>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}): UseQueryResult<TData, TError> & {
    queryKey: QueryKey;
};
/**
 * @summary Get aggregated monitor statistics
 */
export declare const getGetMonitorStatsUrl: () => string;
export declare const getMonitorStats: (options?: RequestInit) => Promise<MonitorStats>;
export declare const getGetMonitorStatsQueryKey: () => readonly ["/api/monitor/stats"];
export declare const getGetMonitorStatsQueryOptions: <TData = Awaited<ReturnType<typeof getMonitorStats>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getMonitorStats>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}) => UseQueryOptions<Awaited<ReturnType<typeof getMonitorStats>>, TError, TData> & {
    queryKey: QueryKey;
};
export type GetMonitorStatsQueryResult = NonNullable<Awaited<ReturnType<typeof getMonitorStats>>>;
export type GetMonitorStatsQueryError = ErrorType<unknown>;
/**
 * @summary Get aggregated monitor statistics
 */
export declare function useGetMonitorStats<TData = Awaited<ReturnType<typeof getMonitorStats>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getMonitorStats>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}): UseQueryResult<TData, TError> & {
    queryKey: QueryKey;
};
/**
 * @summary Get found keys and URLs
 */
export declare const getGetMonitorResultsUrl: (params?: GetMonitorResultsParams) => string;
export declare const getMonitorResults: (params?: GetMonitorResultsParams, options?: RequestInit) => Promise<ResultsPage>;
export declare const getGetMonitorResultsQueryKey: (params?: GetMonitorResultsParams) => readonly ["/api/monitor/results", ...GetMonitorResultsParams[]];
export declare const getGetMonitorResultsQueryOptions: <TData = Awaited<ReturnType<typeof getMonitorResults>>, TError = ErrorType<unknown>>(params?: GetMonitorResultsParams, options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getMonitorResults>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}) => UseQueryOptions<Awaited<ReturnType<typeof getMonitorResults>>, TError, TData> & {
    queryKey: QueryKey;
};
export type GetMonitorResultsQueryResult = NonNullable<Awaited<ReturnType<typeof getMonitorResults>>>;
export type GetMonitorResultsQueryError = ErrorType<unknown>;
/**
 * @summary Get found keys and URLs
 */
export declare function useGetMonitorResults<TData = Awaited<ReturnType<typeof getMonitorResults>>, TError = ErrorType<unknown>>(params?: GetMonitorResultsParams, options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getMonitorResults>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}): UseQueryResult<TData, TError> & {
    queryKey: QueryKey;
};
/**
 * @summary Get only new results from last cycle
 */
export declare const getGetNewResultsUrl: () => string;
export declare const getNewResults: (options?: RequestInit) => Promise<KeyResult[]>;
export declare const getGetNewResultsQueryKey: () => readonly ["/api/monitor/results/new"];
export declare const getGetNewResultsQueryOptions: <TData = Awaited<ReturnType<typeof getNewResults>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getNewResults>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}) => UseQueryOptions<Awaited<ReturnType<typeof getNewResults>>, TError, TData> & {
    queryKey: QueryKey;
};
export type GetNewResultsQueryResult = NonNullable<Awaited<ReturnType<typeof getNewResults>>>;
export type GetNewResultsQueryError = ErrorType<unknown>;
/**
 * @summary Get only new results from last cycle
 */
export declare function useGetNewResults<TData = Awaited<ReturnType<typeof getNewResults>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getNewResults>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}): UseQueryResult<TData, TError> & {
    queryKey: QueryKey;
};
/**
 * @summary Trigger a manual search cycle
 */
export declare const getTriggerCycleUrl: () => string;
export declare const triggerCycle: (options?: RequestInit) => Promise<ActionResponse>;
export declare const getTriggerCycleMutationOptions: <TError = ErrorType<unknown>, TContext = unknown>(options?: {
    mutation?: UseMutationOptions<Awaited<ReturnType<typeof triggerCycle>>, TError, void, TContext>;
    request?: SecondParameter<typeof customFetch>;
}) => UseMutationOptions<Awaited<ReturnType<typeof triggerCycle>>, TError, void, TContext>;
export type TriggerCycleMutationResult = NonNullable<Awaited<ReturnType<typeof triggerCycle>>>;
export type TriggerCycleMutationError = ErrorType<unknown>;
/**
 * @summary Trigger a manual search cycle
 */
export declare const useTriggerCycle: <TError = ErrorType<unknown>, TContext = unknown>(options?: {
    mutation?: UseMutationOptions<Awaited<ReturnType<typeof triggerCycle>>, TError, void, TContext>;
    request?: SecondParameter<typeof customFetch>;
}) => UseMutationResult<Awaited<ReturnType<typeof triggerCycle>>, TError, void, TContext>;
/**
 * @summary Validate a specific found key
 */
export declare const getValidateKeyUrl: (id: string) => string;
export declare const validateKey: (id: string, options?: RequestInit) => Promise<ValidationResult>;
export declare const getValidateKeyMutationOptions: <TError = ErrorType<unknown>, TContext = unknown>(options?: {
    mutation?: UseMutationOptions<Awaited<ReturnType<typeof validateKey>>, TError, {
        id: string;
    }, TContext>;
    request?: SecondParameter<typeof customFetch>;
}) => UseMutationOptions<Awaited<ReturnType<typeof validateKey>>, TError, {
    id: string;
}, TContext>;
export type ValidateKeyMutationResult = NonNullable<Awaited<ReturnType<typeof validateKey>>>;
export type ValidateKeyMutationError = ErrorType<unknown>;
/**
 * @summary Validate a specific found key
 */
export declare const useValidateKey: <TError = ErrorType<unknown>, TContext = unknown>(options?: {
    mutation?: UseMutationOptions<Awaited<ReturnType<typeof validateKey>>, TError, {
        id: string;
    }, TContext>;
    request?: SecondParameter<typeof customFetch>;
}) => UseMutationResult<Awaited<ReturnType<typeof validateKey>>, TError, {
    id: string;
}, TContext>;
/**
 * @summary Get current monitor configuration
 */
export declare const getGetMonitorConfigUrl: () => string;
export declare const getMonitorConfig: (options?: RequestInit) => Promise<MonitorConfig>;
export declare const getGetMonitorConfigQueryKey: () => readonly ["/api/monitor/config"];
export declare const getGetMonitorConfigQueryOptions: <TData = Awaited<ReturnType<typeof getMonitorConfig>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getMonitorConfig>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}) => UseQueryOptions<Awaited<ReturnType<typeof getMonitorConfig>>, TError, TData> & {
    queryKey: QueryKey;
};
export type GetMonitorConfigQueryResult = NonNullable<Awaited<ReturnType<typeof getMonitorConfig>>>;
export type GetMonitorConfigQueryError = ErrorType<unknown>;
/**
 * @summary Get current monitor configuration
 */
export declare function useGetMonitorConfig<TData = Awaited<ReturnType<typeof getMonitorConfig>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getMonitorConfig>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}): UseQueryResult<TData, TError> & {
    queryKey: QueryKey;
};
/**
 * @summary Update monitor configuration
 */
export declare const getUpdateMonitorConfigUrl: () => string;
export declare const updateMonitorConfig: (monitorConfig: MonitorConfig, options?: RequestInit) => Promise<MonitorConfig>;
export declare const getUpdateMonitorConfigMutationOptions: <TError = ErrorType<unknown>, TContext = unknown>(options?: {
    mutation?: UseMutationOptions<Awaited<ReturnType<typeof updateMonitorConfig>>, TError, {
        data: BodyType<MonitorConfig>;
    }, TContext>;
    request?: SecondParameter<typeof customFetch>;
}) => UseMutationOptions<Awaited<ReturnType<typeof updateMonitorConfig>>, TError, {
    data: BodyType<MonitorConfig>;
}, TContext>;
export type UpdateMonitorConfigMutationResult = NonNullable<Awaited<ReturnType<typeof updateMonitorConfig>>>;
export type UpdateMonitorConfigMutationBody = BodyType<MonitorConfig>;
export type UpdateMonitorConfigMutationError = ErrorType<unknown>;
/**
 * @summary Update monitor configuration
 */
export declare const useUpdateMonitorConfig: <TError = ErrorType<unknown>, TContext = unknown>(options?: {
    mutation?: UseMutationOptions<Awaited<ReturnType<typeof updateMonitorConfig>>, TError, {
        data: BodyType<MonitorConfig>;
    }, TContext>;
    request?: SecondParameter<typeof customFetch>;
}) => UseMutationResult<Awaited<ReturnType<typeof updateMonitorConfig>>, TError, {
    data: BodyType<MonitorConfig>;
}, TContext>;
/**
 * @summary Current auto-chain pipeline status
 */
export declare const getGetAutoChainStatusUrl: () => string;
export declare const getAutoChainStatus: (options?: RequestInit) => Promise<AutoChainStatus>;
export declare const getGetAutoChainStatusQueryKey: () => readonly ["/api/monitor/auto-chain/status"];
export declare const getGetAutoChainStatusQueryOptions: <TData = Awaited<ReturnType<typeof getAutoChainStatus>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getAutoChainStatus>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}) => UseQueryOptions<Awaited<ReturnType<typeof getAutoChainStatus>>, TError, TData> & {
    queryKey: QueryKey;
};
export type GetAutoChainStatusQueryResult = NonNullable<Awaited<ReturnType<typeof getAutoChainStatus>>>;
export type GetAutoChainStatusQueryError = ErrorType<unknown>;
/**
 * @summary Current auto-chain pipeline status
 */
export declare function useGetAutoChainStatus<TData = Awaited<ReturnType<typeof getAutoChainStatus>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getAutoChainStatus>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}): UseQueryResult<TData, TError> & {
    queryKey: QueryKey;
};
/**
 * @summary Manually trigger Discovery → ENV pipeline now
 */
export declare const getTriggerAutoChainUrl: () => string;
export declare const triggerAutoChain: (options?: RequestInit) => Promise<AutoChainTriggerResponse>;
export declare const getTriggerAutoChainMutationOptions: <TError = ErrorType<unknown>, TContext = unknown>(options?: {
    mutation?: UseMutationOptions<Awaited<ReturnType<typeof triggerAutoChain>>, TError, void, TContext>;
    request?: SecondParameter<typeof customFetch>;
}) => UseMutationOptions<Awaited<ReturnType<typeof triggerAutoChain>>, TError, void, TContext>;
export type TriggerAutoChainMutationResult = NonNullable<Awaited<ReturnType<typeof triggerAutoChain>>>;
export type TriggerAutoChainMutationError = ErrorType<unknown>;
/**
 * @summary Manually trigger Discovery → ENV pipeline now
 */
export declare const useTriggerAutoChain: <TError = ErrorType<unknown>, TContext = unknown>(options?: {
    mutation?: UseMutationOptions<Awaited<ReturnType<typeof triggerAutoChain>>, TError, void, TContext>;
    request?: SecondParameter<typeof customFetch>;
}) => UseMutationResult<Awaited<ReturnType<typeof triggerAutoChain>>, TError, void, TContext>;
/**
 * @summary Get status of all sources from last cycle
 */
export declare const getGetSourceStatusesUrl: () => string;
export declare const getSourceStatuses: (options?: RequestInit) => Promise<SourceStatus[]>;
export declare const getGetSourceStatusesQueryKey: () => readonly ["/api/monitor/source-statuses"];
export declare const getGetSourceStatusesQueryOptions: <TData = Awaited<ReturnType<typeof getSourceStatuses>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getSourceStatuses>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}) => UseQueryOptions<Awaited<ReturnType<typeof getSourceStatuses>>, TError, TData> & {
    queryKey: QueryKey;
};
export type GetSourceStatusesQueryResult = NonNullable<Awaited<ReturnType<typeof getSourceStatuses>>>;
export type GetSourceStatusesQueryError = ErrorType<unknown>;
/**
 * @summary Get status of all sources from last cycle
 */
export declare function useGetSourceStatuses<TData = Awaited<ReturnType<typeof getSourceStatuses>>, TError = ErrorType<unknown>>(options?: {
    query?: UseQueryOptions<Awaited<ReturnType<typeof getSourceStatuses>>, TError, TData>;
    request?: SecondParameter<typeof customFetch>;
}): UseQueryResult<TData, TError> & {
    queryKey: QueryKey;
};
export {};
//# sourceMappingURL=api.d.ts.map