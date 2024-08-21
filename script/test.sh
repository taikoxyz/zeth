#!/bin/bash

# Array of block numbers
blocks=(
306610 306612 306614 306615 306618 306623 306624 306628 306631 306633
306635 306638 306641 306642 306644 306646 306654 306655 306658 306664
306665 306666 306667 306668 306671 306673 306676 307600 307602 307603
307604 307615 307617 307618 307619 307620 307621 307622 307623 307625
307627 307628 307629 307630 307633 307634 307639 307640 307641 307642
307644
)

# Loop through each block number and run the prove-block.sh script
for block in "${blocks[@]}"; do
    echo "Proving block $block"
    ./script/prove-block.sh taiko_mainnet sp1 "$block" "$block"
    echo "Finished proving block $block"
    echo "------------------------"
done

echo "All blocks have been processed"