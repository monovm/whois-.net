using System.Linq;
using MonoVM.Whois.Configuration;
using MonoVM.Whois.Detection;
using MonoVM.Whois.Detection.Rules;
using MonoVM.Whois.Model;
using Xunit;

namespace MonoVM.Whois.Tests;

public class AvailabilityAnalyzerTests
{
    private static readonly AvailabilityAnalyzer Analyzer = AvailabilityAnalyzer.Default;

    private static DomainAvailabilityStatus Analyze(
        string text,
        string tld = ".com",
        WhoisServerDefinition? server = null,
        WhoisProtocol protocol = WhoisProtocol.Whois43,
        int? httpStatus = null)
        => Analyzer.Analyze(new AvailabilityContext(text, tld, server, protocol, httpStatus)).Status;

    [Fact]
    public void Reads_a_verisign_no_match_as_available()
    {
        const string Reply = """
        No match for "NOTREGISTEREDANYWHERE12345.COM".
        >>> Last update of whois database: 2026-01-01T00:00:00Z <<<

        NOTICE: The expiration date displayed in this record is the date the
        registrar's sponsorship of the domain name registration in the registry is
        currently set to expire.

        TERMS OF USE: You are not authorized to access or query our Whois database.
        """;

        Assert.Equal(DomainAvailabilityStatus.Available, Analyze(Reply, ".com", TestServers.Com));
    }

    [Fact]
    public void Reads_a_verisign_record_as_registered()
    {
        Assert.Equal(DomainAvailabilityStatus.Registered, Analyze(Fixtures.ComRecord, ".com", TestServers.Com));
    }

    [Fact]
    public void Reads_an_rdap_record_as_registered()
    {
        Assert.Equal(
            DomainAvailabilityStatus.Registered,
            Analyze(Fixtures.RdapRecord, ".shop", TestServers.Shop, WhoisProtocol.Rdap, 200));
    }

    [Fact]
    public void Reads_an_rdap_404_as_available()
    {
        const string Reply = """{"errorCode": 404, "title": "Not Found", "rdapConformance": ["rdap_level_0"]}""";

        Assert.Equal(
            DomainAvailabilityStatus.Available,
            Analyze(Reply, ".shop", TestServers.Shop, WhoisProtocol.Rdap, 404));
    }

    [Theory]
    [InlineData("%% Request limit exceeded. Please try again later.")]
    [InlineData("Requests of this client are not permitted. Please use https://www.nic.ch/whois/")]
    [InlineData("This WHOIS service has been retired. Queries are now served via RDAP.")]
    [InlineData("Maximum queries rate reached, please slow down.")]
    public void Never_reads_a_refusal_as_available(string reply)
    {
        var status = Analyze(reply, ".com", TestServers.Com);

        Assert.NotEqual(DomainAvailabilityStatus.Available, status);
        Assert.Equal(DomainAvailabilityStatus.Error, status);
    }

    [Fact]
    public void Never_reads_an_ip_registry_banner_as_available()
    {
        const string Reply = """
        % This is the RIPE Database query service.
        % The objects are in RPSL format.

        %ERROR:101: no entries found
        """;

        // The suffix is mapped to the wrong server. The banner says so, and "no entries found"
        // must not be allowed to answer a question this server was never asked.
        Assert.Equal(DomainAvailabilityStatus.Error, Analyze(Reply, ".ad", TestServers.Com));
    }

    [Fact]
    public void Reads_dotted_keys_that_a_plain_status_match_would_miss()
    {
        const string Reply = """
        domain.............: example.fi
        status.............: Registered
        created............: 12.3.2004
        """;

        Assert.Equal(DomainAvailabilityStatus.Registered, Analyze(Reply, ".fi"));
    }

    [Theory]
    [InlineData("Domain: example.de\nStatus: connect", DomainAvailabilityStatus.Registered)]
    [InlineData("Domain: example.de\nStatus: free", DomainAvailabilityStatus.Available)]
    [InlineData("Domain: example.de\nStatus: invalid", DomainAvailabilityStatus.Registered)]
    public void Understands_denic_wording(string reply, DomainAvailabilityStatus expected)
    {
        Assert.Equal(expected, Analyze(reply, ".de", TestServers.De));
    }

    [Fact]
    public void Reads_a_registry_restriction_notice_as_registered()
    {
        const string Reply = """
        Error code: 01044
        Error message: The domain name you requested has usage restrictions applied.
        """;

        Assert.Equal(DomainAvailabilityStatus.Registered, Analyze(Reply, ".sx"));
    }

    [Fact]
    public void Reads_the_registrys_premium_marker_as_premium()
    {
        var server = WhoisServerDefinition.Create(
            ".example", "socket://whois.example.test", premium: "reserved by the registry");

        Assert.Equal(
            DomainAvailabilityStatus.Premium,
            Analyze("This name is Reserved By The Registry.", ".example", server));
    }

    [Fact]
    public void Treats_an_empty_reply_as_an_error_not_availability()
    {
        Assert.Equal(DomainAvailabilityStatus.Error, Analyze("   \r\n  ", ".com", TestServers.Com));
    }

    [Fact]
    public void Treats_a_recordless_reply_as_available_only_where_the_registry_documents_it()
    {
        const string Banner = """
        % Monaco Telecom Whois Server
        % Terms of use apply.
        """;

        Assert.Equal(DomainAvailabilityStatus.Available, Analyze(Banner, ".mc", TestServers.Mc));

        // The same reply from a registry that has not opted in is not evidence of anything.
        Assert.Equal(DomainAvailabilityStatus.Registered, Analyze(Banner, ".com", TestServers.Com));
    }

    [Fact]
    public void Defaults_to_registered_when_nothing_is_recognised()
    {
        var verdict = Analyzer.Analyze(new AvailabilityContext("something entirely unexpected", ".com"));

        Assert.Equal(DomainAvailabilityStatus.Registered, verdict.Status);
        Assert.Null(verdict.DecidedBy);
    }

    [Fact]
    public void An_empty_available_marker_does_not_match_everything()
    {
        // PHP's strpos() returns 0 for an empty needle, which is not false, which is how a package
        // ends up reporting every domain as available.
        var server = WhoisServerDefinition.Create(".example", "socket://whois.example.test", available: "");

        Assert.Equal(DomainAvailabilityStatus.Registered, Analyze(Fixtures.ComRecord, ".example", server));
    }

    [Fact]
    public void Records_the_rule_that_decided()
    {
        var verdict = Analyzer.Analyze(new AvailabilityContext(Fixtures.ComRecord, ".com", TestServers.Com));

        Assert.NotNull(verdict.DecidedBy);
        Assert.NotEmpty(verdict.Trace);
        Assert.Equal(verdict.DecidedBy, verdict.Trace[verdict.Trace.Count - 1].Rule);
    }

    [Fact]
    public void Keeps_every_rule_when_a_full_trace_is_asked_for()
    {
        var analyzer = new AvailabilityAnalyzer(null, new WhoisOptions { CollectFullTrace = true });
        var verdict = analyzer.Analyze(new AvailabilityContext("no match for anything", ".com"));

        Assert.True(verdict.Trace.Count > 1);
        Assert.Contains(verdict.Trace, entry => entry.Decision == AvailabilityDecision.Continue);
    }

    [Fact]
    public void Runs_its_rules_in_order()
    {
        var orders = Analyzer.Rules.Select(rule => rule.Order).ToList();
        Assert.Equal(orders.OrderBy(order => order).ToList(), orders);
    }

    [Fact]
    public void Accepts_an_extra_rule()
    {
        var rules = AvailabilityAnalyzer.CreateDefaultRules();
        rules.Add(new AlwaysPremiumRule());

        var analyzer = new AvailabilityAnalyzer(rules);
        var verdict = analyzer.Analyze(new AvailabilityContext("nothing recognisable here", ".example"));

        Assert.Equal(DomainAvailabilityStatus.Premium, verdict.Status);
        Assert.Equal("always-premium", verdict.DecidedBy);
    }

    private sealed class AlwaysPremiumRule : AvailabilityRule
    {
        public override string Name => "always-premium";

        public override int Order => AvailabilityRuleOrder.EmptyReply + 1;

        public override AvailabilityRuleResult Evaluate(AvailabilityContext context)
            => AvailabilityRuleResult.Premium("the test says so");
    }
}
