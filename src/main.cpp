#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <nanobind/stl/vector.h>

#include <vector>
#include <atomic>
#include <thread>

#include "include/engine.hpp"

namespace nb = nanobind;
using namespace fastscrub;

NB_MODULE(fastscrub_backend, m) {
    m.doc() = "High-performance PII scrubbing C++ backend";

    nb::class_<Engine>(m, "Engine")
        // Expose constructor with default argument for worker_count
        .def(nb::init<unsigned>(), nb::arg("worker_count") = 0)
        
        // Sequential scrub
        .def("scrub", [](const Engine& engine, nb::str py_input) {
            std::string_view input = nb::cast<std::string_view>(py_input);
            auto out = engine.scrub(input);
            if (out.has_value()) {
                PyObject* py_s = PyUnicode_DecodeUTF8(out->data(), (Py_ssize_t)out->size(), "replace");
                if (!py_s) throw std::runtime_error("Failed to decode string to Python UTF-8");
                return nb::steal<nb::str>(py_s);
            } else {
                return py_input; // ZERO COPY!
            }
        }, nb::arg("input"), "Scrub a single string sequentially.")
             
        // Parallel bulk scrub with GIL released
        .def("scrub_bulk", [](const Engine& engine, nb::str py_input) {
            std::string_view input = nb::cast<std::string_view>(py_input);
            std::optional<std::string> out;
            {
                nb::gil_scoped_release release;
                out = engine.scrub_bulk(input);
            }
            if (out.has_value()) {
                PyObject* py_s = PyUnicode_DecodeUTF8(out->data(), (Py_ssize_t)out->size(), "replace");
                if (!py_s) throw std::runtime_error("Failed to decode string to Python UTF-8");
                return nb::steal<nb::str>(py_s);
            } else {
                return py_input; // ZERO COPY!
            }
        }, nb::arg("input"),
        "Scrub a large text buffer in parallel, safely releasing the GIL.");

    // Zero-copy, GIL-free Batch Processing
    m.def("scrub_batch", [](nb::list py_list, unsigned worker_count) {
        unsigned workers = worker_count == 0 ? std::thread::hardware_concurrency() : worker_count;
        if (workers == 0) workers = 4;

        size_t num_items = nb::len(py_list);
        std::vector<std::string_view> inputs;
        inputs.reserve(num_items);
        std::vector<nb::handle> py_handles(num_items);

        // 1. Extract raw string pointers from Python list natively (Zero-Copy)
        for (size_t i = 0; i < num_items; ++i) {
            py_handles[i] = py_list[i];
            inputs.push_back(nb::cast<std::string_view>(py_handles[i]));
        }

        std::vector<std::optional<std::string>> outputs(num_items);
        std::atomic<size_t> next_idx{0};
        Engine engine(workers);

        {
            // 2. completely free the Python GIL for this thread lifetime!
            nb::gil_scoped_release release; 
            
            std::vector<std::jthread> threads;
            for (unsigned t = 0; t < workers; ++t) {
                threads.emplace_back([&]() {
                    while (true) {
                        size_t idx = next_idx.fetch_add(1, std::memory_order_relaxed);
                        if (idx >= inputs.size()) break;
                        outputs[idx] = engine.scrub(inputs[idx]);
                    }
                });
            }
        } // 3. All threads join here natively, then the GIL is re-acquired.

        // 4. Zero-Copy return logic
        nb::list py_out;
        for (size_t i = 0; i < outputs.size(); ++i) {
            if (outputs[i].has_value()) {
                PyObject* py_s = PyUnicode_DecodeUTF8(outputs[i]->data(), (Py_ssize_t)outputs[i]->size(), "replace");
                if (!py_s) throw std::runtime_error("Failed to decode string to Python UTF-8");
                py_out.append(nb::steal<nb::str>(py_s));
            } else {
                py_out.append(py_handles[i]); // ZERO COPY!
            }
        }

        return py_out;
    }, nb::arg("inputs"), nb::arg("worker_count") = 0, "Processes an array of strings in parallel with zero thread lock contention.");
}
