using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MonoVM.Whois.Abstractions;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Detection;
using MonoVM.Whois.Parsing;
using MonoVM.Whois.Registry;
using MonoVM.Whois.Transport;

namespace MonoVM.Whois.DependencyInjection;

/// <summary>Registers the library with a dependency-injection container.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IWhoisClient"/> and everything behind it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every collaborator is registered with <c>TryAdd</c>, so replacing one is a matter of
    /// registering your own first — no options flag and no fork:
    /// </para>
    /// <code>
    /// services.AddSingleton&lt;IAvailabilityAnalyzer, MyAnalyzer&gt;();
    /// services.AddWhois();
    /// </code>
    /// <para>
    /// Everything is a singleton. The suffix table, the compiled patterns and the response cache
    /// are all expensive to build and safe to share, and a per-request client would throw away the
    /// cache and the rate-limiter state that keep a registry from blocking you.
    /// </para>
    /// </remarks>
    /// <param name="services">The container.</param>
    /// <param name="configure">Optional configuration, applied over the defaults.</param>
    public static IServiceCollection AddWhois(this IServiceCollection services, Action<WhoisOptions>? configure = null)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddOptions<WhoisOptions>();

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton<IWhoisServerRegistry>(provider =>
            WhoisServerRegistry.FromOptions(provider.GetRequiredService<IOptions<WhoisOptions>>().Value));

        services.TryAddSingleton<IDomainNameParser>(provider =>
            new DomainNameParser(provider.GetRequiredService<IWhoisServerRegistry>()));

        services.TryAddSingleton<IWhoisResponseCache>(provider =>
            provider.GetRequiredService<IOptions<WhoisOptions>>().Value.EnableCache
                ? new MemoryWhoisResponseCache()
                : NullWhoisResponseCache.Instance);

        services.TryAddSingleton<IAvailabilityAnalyzer>(provider =>
            new AvailabilityAnalyzer(null, provider.GetRequiredService<IOptions<WhoisOptions>>().Value));

        services.TryAddSingleton<IWhoisRecordParser>(_ => CompositeWhoisRecordParser.CreateDefault());

        services.TryAddSingleton<IWhoisTransportFactory>(provider => new WhoisTransportFactory(
            provider.GetRequiredService<IOptions<WhoisOptions>>().Value,
            provider.GetRequiredService<IWhoisResponseCache>(),
            httpClient: null,
            loggerFactory: provider.GetService<ILoggerFactory>()));

        services.TryAddSingleton<WhoisClient>(provider => new WhoisClient(
            provider.GetRequiredService<IOptions<WhoisOptions>>().Value,
            provider.GetRequiredService<IWhoisServerRegistry>(),
            provider.GetRequiredService<IWhoisTransportFactory>(),
            provider.GetRequiredService<IAvailabilityAnalyzer>(),
            provider.GetRequiredService<IWhoisRecordParser>(),
            provider.GetRequiredService<IDomainNameParser>()));

        services.TryAddSingleton<IWhoisClient>(provider => provider.GetRequiredService<WhoisClient>());
        services.TryAddSingleton<IWhoisLookup>(provider => provider.GetRequiredService<WhoisClient>());
        services.TryAddSingleton<IDomainAvailabilityChecker>(provider => provider.GetRequiredService<WhoisClient>());

        return services;
    }

    /// <summary>
    /// Registers the library and sends RDAP requests through an <c>HttpClient</c> you supply.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Worth doing in a long-lived host: <c>IHttpClientFactory</c> handles connection recycling and
    /// DNS changes, and lets Polly or your own handlers sit in front of the RDAP calls. Passing a
    /// factory delegate rather than a client name keeps <c>Microsoft.Extensions.Http</c> off this
    /// package's dependency list, while giving you exactly the same wiring:
    /// </para>
    /// <code>
    /// services.AddHttpClient("rdap");
    /// services.AddWhois(sp =&gt; sp.GetRequiredService&lt;IHttpClientFactory&gt;().CreateClient("rdap"));
    /// </code>
    /// </remarks>
    /// <param name="services">The container.</param>
    /// <param name="httpClientFactory">Resolves the client to send RDAP requests with.</param>
    /// <param name="configure">Optional configuration, applied over the defaults.</param>
    public static IServiceCollection AddWhois(
        this IServiceCollection services,
        Func<IServiceProvider, System.Net.Http.HttpClient> httpClientFactory,
        Action<WhoisOptions>? configure = null)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (httpClientFactory is null)
        {
            throw new ArgumentNullException(nameof(httpClientFactory));
        }

        services.TryAddSingleton<IWhoisTransportFactory>(provider => new WhoisTransportFactory(
            provider.GetRequiredService<IOptions<WhoisOptions>>().Value,
            provider.GetRequiredService<IWhoisResponseCache>(),
            httpClientFactory(provider),
            provider.GetService<ILoggerFactory>()));

        return services.AddWhois(configure);
    }
}
