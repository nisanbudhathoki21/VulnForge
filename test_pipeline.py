from engine.discovery import DiscoveryEngine
from engine.endpoint_pipeline import prepare_endpoints


engine = DiscoveryEngine(
    "https://pioneereducational.edu.np",
    max_depth=2,
    max_urls=100,
    timeout=10,
    delay=0.5,
    quiet=False,
)

result = engine.run()

pipeline = prepare_endpoints(
    result["endpoints"]
)

print()
print("=" * 70)
print("VULNFORGE ENDPOINT PIPELINE")
print("=" * 70)

print(
    "Discovered:",
    len(result["endpoints"])
)

print(
    "Normalized:",
    pipeline["endpoint_count"]
)

print(
    "Test cases:",
    pipeline["test_count"]
)

print()
print("ENDPOINTS")
print("-" * 70)

for endpoint in pipeline["endpoints"]:

    print(
        endpoint.method,
        endpoint.normalized_url,
        "|",
        endpoint.endpoint_type,
        "| params:",
        endpoint.parameters,
        "| tests:",
        endpoint.test_categories,
    )

print()
print("TEST PLAN")
print("-" * 70)

for test in pipeline["test_plan"]:

    print(
        test["method"],
        test["endpoint"],
        "| parameter:",
        test["parameter"],
        "| category:",
        test["parameter_category"],
        "| tests:",
        test["tests"],
    )
