"""Tests for subdomainenum.streaming – background DNS resolver pipeline."""

from __future__ import annotations

import threading
import time

from subdomainenum.streaming import StreamingResolver


class TestStreamingResolverSubmit:
    def test_submit_returns_none_and_queues_fqdn(self) -> None:
        calls: list[str] = []

        def fake_resolver(fqdn: str) -> list[str]:
            calls.append(fqdn)
            return ["1.2.3.4"]

        resolver = StreamingResolver(resolver=fake_resolver)
        resolver.submit("sub.example.com")
        cache = resolver.collect()
        resolver.shutdown()
        assert cache == {"sub.example.com": ["1.2.3.4"]}
        assert calls == ["sub.example.com"]

    def test_duplicate_submit_resolves_once(self) -> None:
        calls: list[str] = []

        def fake_resolver(fqdn: str) -> list[str]:
            calls.append(fqdn)
            return ["1.1.1.1"]

        resolver = StreamingResolver(resolver=fake_resolver)
        resolver.submit("dup.example.com")
        resolver.submit("dup.example.com")
        resolver.submit("DUP.example.com")  # case-insensitive dedup
        resolver.collect()
        resolver.shutdown()
        assert calls == ["dup.example.com"]

    def test_blank_input_is_ignored(self) -> None:
        calls: list[str] = []

        def fake_resolver(fqdn: str) -> list[str]:
            calls.append(fqdn)
            return []

        resolver = StreamingResolver(resolver=fake_resolver)
        resolver.submit("")
        resolver.submit("   ")
        resolver.collect()
        resolver.shutdown()
        assert calls == []

    def test_submit_after_shutdown_is_noop(self) -> None:
        calls: list[str] = []

        def fake_resolver(fqdn: str) -> list[str]:
            calls.append(fqdn)
            return []

        resolver = StreamingResolver(resolver=fake_resolver)
        resolver.shutdown()
        resolver.submit("late.example.com")
        assert calls == []


class TestStreamingResolverCollect:
    def test_collect_submits_and_waits_for_given_fqdns(self) -> None:
        resolver = StreamingResolver(resolver=lambda f: [f"ip-of-{f}"])
        cache = resolver.collect(["a.example.com", "b.example.com"])
        resolver.shutdown()
        assert cache == {
            "a.example.com": ["ip-of-a.example.com"],
            "b.example.com": ["ip-of-b.example.com"],
        }

    def test_collect_returns_empty_list_when_resolver_raises(self) -> None:
        def failing_resolver(fqdn: str) -> list[str]:
            raise RuntimeError("DNS kaboom")

        resolver = StreamingResolver(resolver=failing_resolver)
        resolver.submit("crash.example.com")
        cache = resolver.collect()
        resolver.shutdown()
        assert cache == {"crash.example.com": []}

    def test_collect_no_args_returns_existing_cache(self) -> None:
        resolver = StreamingResolver(resolver=lambda f: [f"addr-{f}"])
        resolver.submit("only.example.com")
        cache = resolver.collect()
        resolver.shutdown()
        assert cache == {"only.example.com": ["addr-only.example.com"]}


class TestStreamingResolverCollectSubset:
    def test_subset_blocks_only_on_requested_fqdns(self) -> None:
        """collect_subset should not wait for unrelated in-flight futures."""
        slow_event = threading.Event()
        fast_event = threading.Event()

        def resolver_fn(fqdn: str) -> list[str]:
            if fqdn == "slow.example.com":
                slow_event.wait(timeout=5.0)
                return ["9.9.9.9"]
            fast_event.set()
            return ["1.1.1.1"]

        resolver = StreamingResolver(resolver=resolver_fn)
        resolver.submit("slow.example.com")
        subset = resolver.collect_subset(["fast.example.com"])
        assert subset == {"fast.example.com": ["1.1.1.1"]}
        assert fast_event.is_set()
        # Release the slow worker so we can shut down cleanly.
        slow_event.set()
        resolver.collect()
        resolver.shutdown()

    def test_subset_ignores_blank_entries(self) -> None:
        resolver = StreamingResolver(resolver=lambda f: ["2.2.2.2"])
        subset = resolver.collect_subset(["", "   ", "ok.example.com"])
        resolver.shutdown()
        assert subset == {"ok.example.com": ["2.2.2.2"]}

    def test_subset_returns_empty_list_on_resolver_exception(self) -> None:
        def failing(fqdn: str) -> list[str]:
            raise ValueError("boom")

        resolver = StreamingResolver(resolver=failing)
        subset = resolver.collect_subset(["x.example.com"])
        resolver.shutdown()
        assert subset == {"x.example.com": []}


class TestStreamingResolverContextManager:
    def test_context_manager_shuts_down_on_exit(self) -> None:
        calls: list[str] = []

        def fake_resolver(fqdn: str) -> list[str]:
            calls.append(fqdn)
            return ["1.2.3.4"]

        with StreamingResolver(resolver=fake_resolver) as resolver:
            resolver.submit("ctx.example.com")
            resolver.collect()
        # Post-shutdown submit is a no-op.
        resolver.submit("after.example.com")
        assert calls == ["ctx.example.com"]


class TestStreamingResolverConcurrency:
    def test_many_concurrent_submits_dedupe_correctly(self) -> None:
        """Stress test: N threads submit the same FQDNs → each resolved once."""
        seen_count: dict[str, int] = {}
        lock = threading.Lock()

        def counting(fqdn: str) -> list[str]:
            with lock:
                seen_count[fqdn] = seen_count.get(fqdn, 0) + 1
            time.sleep(0.001)
            return ["1.1.1.1"]

        resolver = StreamingResolver(resolver=counting)
        fqdns = [f"sub{i}.example.com" for i in range(5)]

        def worker() -> None:
            for f in fqdns:
                resolver.submit(f)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        cache = resolver.collect()
        resolver.shutdown()
        assert set(cache.keys()) == set(fqdns)
        for f in fqdns:
            assert seen_count[f] == 1, f"{f} was resolved {seen_count[f]} times, expected 1"
