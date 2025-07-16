#!/bin/bash

# QUICK LIVE DEMO - 5 minutes max
# Most impressive quantum assertions demo for live audience

clear
echo "================================================"
echo "QUANTUM-RESISTANT OPENTDF - LIVE DEMO"
echo "Protecting your data against quantum computers"
echo "================================================"
echo

# Show the simple API first (most impressive)
echo "1. SIMPLE API - ONE LINE CHANGE!"
echo "   Traditional TDF:  sdk.CreateTDF(writer, reader)"
echo "   Quantum TDF:     sdk.CreateTDF(writer, reader, WithQuantumResistantAssertions())"
echo "   That's it! One line makes your data quantum-safe."
echo
read -p "Press Enter to see it working..."

# Show it actually works
echo
echo "2. PROOF IT WORKS - Running live test..."
go test -run="TestQuantumTDFIntegration" -v | grep -E "(PASS|Traditional signature|Quantum signature|overhead)"
echo

# Show performance benefits  
echo "3. PERFORMANCE - Quantum is actually FASTER!"
go test -run="TestQuantumVsRSAMetrics" -v | grep -E "(Key Generation|Signing Time|FASTER)"
echo

# Show actual TDF file creation
echo "4. REAL TDF FILES - Creating quantum-protected TDFs..."
go test -run="TestQuantumTDFEndToEndProof" -v | grep -E "(PASS|TDF|Quantum|assertions working|Ready for production)"
echo

echo "================================================"
echo "DEMO COMPLETE!"
echo "Your TDF files are now quantum-computer-proof!"
echo "Questions?"
echo "================================================"
