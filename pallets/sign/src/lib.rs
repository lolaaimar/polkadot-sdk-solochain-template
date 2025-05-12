#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use sp_core::crypto::KeyTypeId;

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"sign");

pub mod crypto {
    use super::KEY_TYPE;
    use sp_core::ed25519::Signature as Ed25519Signature;
    use sp_runtime::{
        app_crypto::{app_crypto, ed25519},
        traits::Verify,
        MultiSignature, MultiSigner,
    };
    app_crypto!(ed25519, KEY_TYPE);

    pub struct SignAuthId;

    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for SignAuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::ed25519::Signature;
        type GenericPublic = sp_core::ed25519::Public;
    }

    impl frame_system::offchain::AppCrypto<<Ed25519Signature as Verify>::Signer, Ed25519Signature>
        for SignAuthId
    {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::ed25519::Signature;
        type GenericPublic = sp_core::ed25519::Public;
    }
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::{
        offchain::{AppCrypto, CreateSignedTransaction, Signer, SignMessage},
        pallet_prelude::*,
    };
	use hex::ToHex;
	use scale_info::prelude::{vec, boxed::Box};

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	}

	#[pallet::storage]
	pub type Something<T> = StorageValue<_, u32>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		SomethingStored {
			something: u32,
			who: T::AccountId,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		NoneValue,
		StorageOverflow,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight((0, Pays::No))]
		pub fn do_something(origin: OriginFor<T>, something: u32) -> DispatchResult {
			let who = ensure_signed(origin)?;

			Something::<T>::put(something);

			Self::deposit_event(Event::SomethingStored { something, who });

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight((0, Pays::No))]
		pub fn cause_error(origin: OriginFor<T>) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			match Something::<T>::get() {
				None => Err(Error::<T>::NoneValue.into()),
				Some(old) => {
					let new = old.checked_add(1).ok_or(Error::<T>::StorageOverflow)?;
					Something::<T>::put(new);
					Ok(())
				},
			}
		}
	}	

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		// Offchain worker has access to the Account inserted for the "sign" key,
		// and thus, the private key associated which will be used to sign. 
		fn offchain_worker(_n: BlockNumberFor<T>) {
			log::info!("Starting offchain worker to sign a message");
            let mut acc_list = Signer::<T, T::AuthorityId>::keystore_accounts();
            match acc_list.next() {
                Some(signer_account) if acc_list.next().is_none() => {
                    let signer = Signer::<T, T::AuthorityId>::all_accounts()
                        .with_filter(vec![signer_account.clone().public]);
                    if signer.can_sign() {
						if let Some(signed_message) = signer.sign_message(b"some_message").pop() {
							let account_hex: Box<str> = signed_message.0.id.encode().encode_hex();
							log::info!("Account signed: {:?}", account_hex);
							let signature_hex: Box<str> = signed_message.1.encode().encode_hex();
							log::info!("Signed message: {}", signature_hex);
						} else {
							log::error!("Couldn't sign");
						}
                    }
                }
                Some(_accounts) => log::error!("More than one account. Expected only one"),
                None => log::error!("No account available"),
            }
		}
	}
}
